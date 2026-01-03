-- Log inbound webhook deliveries for observability
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_source_id UUID NOT NULL REFERENCES webhook_sources(id) ON DELETE CASCADE,
  subscription_id UUID REFERENCES webhook_subscriptions(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivery_status TEXT NOT NULL CHECK (delivery_status IN ('received', 'routed', 'dropped', 'errored')),
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook_source_id
  ON webhook_deliveries (webhook_source_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_subscription_id
  ON webhook_deliveries (subscription_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_received_at
  ON webhook_deliveries (received_at);

-- Rollback:
--   DROP INDEX IF EXISTS idx_webhook_deliveries_received_at;
--   DROP INDEX IF EXISTS idx_webhook_deliveries_subscription_id;
--   DROP INDEX IF EXISTS idx_webhook_deliveries_webhook_source_id;
--   DROP TABLE IF EXISTS webhook_deliveries;
