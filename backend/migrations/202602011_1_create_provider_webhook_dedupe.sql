-- Track provider webhook delivery ids for idempotency
CREATE TABLE IF NOT EXISTS provider_webhook_dedupe (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  delivery_id TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, delivery_id)
);

CREATE INDEX IF NOT EXISTS idx_provider_webhook_dedupe_received_at
  ON provider_webhook_dedupe (received_at);

-- Rollback:
--   DROP INDEX IF EXISTS idx_provider_webhook_dedupe_received_at;
--   DROP TABLE IF EXISTS provider_webhook_dedupe;
