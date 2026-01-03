-- Create webhook_subscriptions for source/event/workflow trigger mappings
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_source_id UUID NOT NULL REFERENCES webhook_sources(id) ON DELETE CASCADE,
  workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  trigger_node_id UUID NOT NULL,
  event_type TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (webhook_source_id, workflow_id, trigger_node_id, event_type)
);

CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_source_event
  ON webhook_subscriptions (webhook_source_id, event_type);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'update_webhook_subscriptions_updated_at'
  ) THEN
    CREATE TRIGGER update_webhook_subscriptions_updated_at
    BEFORE UPDATE ON webhook_subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
  END IF;
END $$ LANGUAGE plpgsql;

-- Rollback:
--   DROP TRIGGER IF EXISTS update_webhook_subscriptions_updated_at ON webhook_subscriptions;
--   DROP INDEX IF EXISTS idx_webhook_subscriptions_source_event;
--   DROP TABLE IF EXISTS webhook_subscriptions;
