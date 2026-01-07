-- Drop legacy workflow-scoped webhook salt (no longer used)
ALTER TABLE workflows
DROP COLUMN IF EXISTS webhook_salt;
-- Rollback:
-- ALTER TABLE workflows
-- ADD COLUMN webhook_salt UUID NOT NULL DEFAULT gen_random_uuid();
