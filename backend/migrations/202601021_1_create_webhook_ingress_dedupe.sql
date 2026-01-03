-- Track inbound webhook deliveries for ingress deduplication
CREATE TABLE IF NOT EXISTS webhook_ingress_dedupe (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID NOT NULL REFERENCES webhook_sources(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload_sha256 BYTEA NOT NULL,
  signature TEXT NOT NULL,
  timestamp_floor TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source_id, event_type, payload_sha256, signature, timestamp_floor)
);

CREATE INDEX IF NOT EXISTS idx_webhook_ingress_dedupe_lookup
  ON webhook_ingress_dedupe (source_id, event_type, timestamp_floor, payload_sha256);

CREATE INDEX IF NOT EXISTS idx_webhook_ingress_dedupe_timestamp_floor
  ON webhook_ingress_dedupe (timestamp_floor);

-- Rollback:
--   DROP INDEX IF EXISTS idx_webhook_ingress_dedupe_timestamp_floor;
--   DROP INDEX IF EXISTS idx_webhook_ingress_dedupe_lookup;
--   DROP TABLE IF EXISTS webhook_ingress_dedupe;
