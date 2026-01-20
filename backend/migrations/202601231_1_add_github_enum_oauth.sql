ALTER TYPE oauth_connection_provider ADD VALUE IF NOT EXISTS 'github';

-- Rollback:
--   -- Enum values cannot be removed without recreating the type.
--   -- Create a new enum without 'github', migrate dependent columns, and drop the old type.
