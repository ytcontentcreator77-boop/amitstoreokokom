import type { Env } from "./env";
import type { Settings } from "./settings";

const IV = new TextEncoder().encode("@@@@&&&&####$$$$");
const enc = new TextEncoder();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const keyBytes = (key: string) => enc.encode(key);

function sortedString(params: Record<string, unknown>): string {
  return Object.keys(params).sort().map(k => { const v=params[k]; return `${k}=${v && typeof v === "object" ? JSON.stringify(v) : v ?? ""}`; }).join("&");
}
async function hmac(data: string, key: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", keyBytes(key), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
async function encrypt(text: string, key: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", keyBytes(key), {name:"AES-CBC"}, false, ["encrypt"]);
  return b64(new Uint8Array(await crypto.subtle.encrypt({name:"AES-CBC",iv:IV},k,enc.encode(text))));
}
async function decrypt(value: string, key: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", keyBytes(key), {name:"AES-CBC"}, false, ["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({name:"AES-CBC",iv:IV},k,unb64(value)));
}
export async function paytmSignature(params: Record<string, unknown>, key: string): Promise<string> {
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(4)), x => "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[x % 62]).join("");
  const digest = await hmac(`${sortedString(params)}|${salt}`, key);
  return encrypt([...digest].map(x=>x.toString(16).padStart(2,"0")).join("")+salt,key);
}
export async function verifyPaytmSignature(params: Record<string, unknown>, key: string, signature: string): Promise<boolean> {
  try {
    const plain = await decrypt(signature,key);
    const salt = plain.slice(-4), expected = [...await hmac(`${sortedString(params)}|${salt}`,key)].map(x=>x.toString(16).padStart(2,"0")).join("");
    return plain.slice(0,-4) === expected;
  } catch { return false; }
}
export const paytmHost = (s: Settings) => s.paytm_environment === "staging" ? "https://securestage.paytmpayments.com" : "https://secure.paytmpayments.com";
export async function initiatePaytm(env: Env, s: Settings, userId: number, amount: number) {
  if (!s.paytm_mid || !s.paytm_merchant_key) throw new Error("PAYTM_NOT_CONFIGURED");
  const orderId = `AMIT${Date.now()}${crypto.randomUUID().replace(/-/g,"").slice(0,8)}`;
  const body = {
    requestType:"Payment", mid:s.paytm_mid, websiteName:(s.paytm_environment==="staging" && (!s.paytm_website_name || s.paytm_website_name==="DEFAULT")) ? "WEBSTAGING" : (s.paytm_website_name || "DEFAULT"),
    orderId, txnAmount:{value:amount.toFixed(2),currency:"INR"}, userInfo:{custId:String(userId)}
  };
  const signature = await paytmSignature(body,s.paytm_merchant_key);
  const host = paytmHost(s);
  const response = await fetch(`${host}/theia/api/v1/initiateTransaction?mid=${encodeURIComponent(s.paytm_mid)}&orderId=${encodeURIComponent(orderId)}`,{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({body,head:{signature}})
  });
  const data:any = await response.json().catch(()=>null);
  if (!response.ok || data?.body?.resultInfo?.resultStatus !== "S" || !data?.body?.txnToken) {
    throw new Error(data?.body?.resultInfo?.resultMsg || "PAYTM_INITIATION_FAILED");
  }
  await env.DB.prepare("INSERT INTO paytm_transactions(order_id,user_id,amount_inr,status,created_at) VALUES(?1,?2,?3,'pending',?4)")
    .bind(orderId,userId,amount,Math.floor(Date.now()/1000)).run();
  return {mid:s.paytm_mid,orderId,txnToken:data.body.txnToken,amount:amount.toFixed(2),checkoutScript:`${host}/merchantpgpui/checkoutjs/merchants/${encodeURIComponent(s.paytm_mid)}.js`};
}
export async function verifyPaytmOrder(env: Env, s: Settings, orderId: string, userId: number) {
  const tx = await env.DB.prepare("SELECT * FROM paytm_transactions WHERE order_id=?1 AND user_id=?2").bind(orderId,userId).first<any>();
  if (!tx) throw new Error("PAYMENT_NOT_FOUND");
  if (tx.status === "paid") return {ok:true};
  if (tx.status === "failed") throw new Error("PAYMENT_FAILED");
  const body = {mid:s.paytm_mid,orderId};
  const signature = await paytmSignature(body,s.paytm_merchant_key);
  const host = paytmHost(s);
  const response = await fetch(`${host}/v3/order/status?mid=${encodeURIComponent(s.paytm_mid)}&orderId=${encodeURIComponent(orderId)}`,{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({body,head:{signature}})
  });
  const data:any = await response.json().catch(()=>null);
  const responseBody = data?.body;
  if (!response.ok || !responseBody || !await verifyPaytmSignature(responseBody,s.paytm_merchant_key,String(data?.head?.signature||""))) {
    throw new Error("PAYTM_STATUS_UNVERIFIED");
  }
  const status = String(responseBody.resultInfo?.resultStatus || responseBody.txnStatus || "");
  const paid = status === "TXN_SUCCESS" || status === "S";
  const failed = status === "TXN_FAILURE" || status === "F";
  if (paid) {
    const rawAmount = responseBody.txnAmount;
    const paidAmount = Number(typeof rawAmount === "object" ? rawAmount?.value : rawAmount ?? 0);
    if (Math.abs(paidAmount-Number(tx.amount_inr)) > 0.009 || String(responseBody.mid)!==String(s.paytm_mid) || String(responseBody.orderId)!==orderId) throw new Error("PAYTM_AMOUNT_MISMATCH");
    const now=Math.floor(Date.now()/1000);
    await env.DB.batch([
      env.DB.prepare("UPDATE paytm_transactions SET status='paid',txn_id=?2,verified_at=?3 WHERE order_id=?1 AND status='pending'").bind(orderId,String(responseBody.txnId||""),now),
      env.DB.prepare("UPDATE users SET balance_inr=balance_inr+?2 WHERE id=?1 AND changes()=1").bind(userId,Number(tx.amount_inr)),
      env.DB.prepare("INSERT INTO inr_ledger(user_id,delta_inr,kind,ref,note,created_at) SELECT ?1,?2,'topup',NULL,?3,?4 WHERE changes()=1").bind(userId,Number(tx.amount_inr),`Paytm payment ${orderId}`,now)
    ]);
    return {ok:true};
  }
  if (failed) {
    await env.DB.prepare("UPDATE paytm_transactions SET status='failed',verified_at=?2 WHERE order_id=?1 AND status='pending'").bind(orderId,Math.floor(Date.now()/1000)).run();
    throw new Error("PAYMENT_FAILED");
  }
  return {ok:false,pending:true};
}
