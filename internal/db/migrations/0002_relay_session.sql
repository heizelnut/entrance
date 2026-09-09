-- 0002: link relay audit rows to live sessions so rows are pruned when a
-- session closes (the table is session history, not a permanent audit log in
-- phase 1; a bounded retention job is phase 2).
ALTER TABLE relays ADD COLUMN session_id TEXT;
CREATE INDEX idx_relays_session ON relays(session_id);