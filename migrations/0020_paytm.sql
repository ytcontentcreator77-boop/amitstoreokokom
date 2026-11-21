CREATE TABLE IF NOT EXISTS paytm_transactions (
  order_id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount_inr REAL NOT NULL CHECK(amount_inr > 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed')),
  txn_id TEXT,
  created_at INTEGER NOT NULL,
  verified_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_paytm_transactions_user ON paytm_transactions(user_id, created_at DESC);
