-- Create webhook_sources for workspace-scoped webhook registration
CREATE TABLE IF NOT EXISTS webhook_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  secret TEXT NOT NULL,
  require_hmac BOOLEAN NOT NULL DEFAULT false,
  replay_window_sec INTEGER NOT NULL DEFAULT 300,
  last_seen_at TIMESTAMPTZ,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, name)
);

CREATE INDEX IF NOT EXISTS idx_webhook_sources_workspace_id
  ON webhook_sources (workspace_id);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'update_webhook_sources_updated_at'
  ) THEN
    CREATE TRIGGER update_webhook_sources_updated_at
    BEFORE UPDATE ON webhook_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
  END IF;
END $$ LANGUAGE plpgsql;

-- Rollback:
--   DROP TRIGGER IF EXISTS update_webhook_sources_updated_at ON webhook_sources;
--   DROP INDEX IF EXISTS idx_webhook_sources_workspace_id;
--   DROP TABLE IF EXISTS webhook_sources;
