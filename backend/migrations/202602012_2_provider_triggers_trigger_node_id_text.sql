-- Ensure provider trigger node IDs can store non-UUID frontend node identifiers.
ALTER TABLE provider_triggers
  ALTER COLUMN trigger_node_id TYPE TEXT
  USING trigger_node_id::text;

-- Rollback:
--   ALTER TABLE provider_triggers
--     ALTER COLUMN trigger_node_id TYPE UUID
--     USING NULLIF(trigger_node_id, '')::uuid;
--   -- If any stored trigger_node_id values are not valid UUIDs, this rollback will fail.
