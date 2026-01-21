-- Create enum for provider trigger providers
CREATE TYPE provider_trigger_provider AS ENUM ('github');

-- Create the provider_triggers table
CREATE TABLE IF NOT EXISTS provider_triggers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
  provider provider_trigger_provider NOT NULL,
  workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
  trigger_node_id UUID NOT NULL,
  event_type TEXT NOT NULL,
  installation_id TEXT NULL,
  repository_id TEXT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT provider_triggers_at_least_one_routing_key 
    CHECK (installation_id IS NOT NULL OR repository_id IS NOT NULL),
  UNIQUE (workspace_id, provider, workflow_id, trigger_node_id, event_type)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_provider_triggers_provider_installation 
  ON provider_triggers (provider, installation_id, event_type) 
  WHERE installation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_provider_triggers_provider_repository 
  ON provider_triggers (provider, repository_id, event_type) 
  WHERE repository_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_provider_triggers_workflow 
  ON provider_triggers (workflow_id);

CREATE INDEX IF NOT EXISTS idx_provider_triggers_trigger_node 
  ON provider_triggers (trigger_node_id);

-- Add updated_at trigger (follow existing pattern)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'update_provider_triggers_updated_at'
  ) THEN
    CREATE TRIGGER update_provider_triggers_updated_at
    BEFORE UPDATE ON provider_triggers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
  END IF;
END $$ LANGUAGE plpgsql;