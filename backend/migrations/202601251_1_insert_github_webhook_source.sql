INSERT INTO webhook_sources (
    id,
    workspace_id,
    name,
    secret,
    require_hmac,
    replay_window_sec,
    enabled,
    created_at,
    updated_at
)
VALUES (
    '73600cad-2781-4b57-a644-9e829d13535c',
    'e2bf3061-8056-430b-942a-f253c9898e17',
    'GitHub',
    'changeme',
    TRUE,
    300,
    TRUE,
    '2026-01-21 23:00:29.44177+00',
    '2026-01-22 01:18:26.690299+00'
)
ON CONFLICT (workspace_id, name)
DO UPDATE SET
    secret = EXCLUDED.secret,
    require_hmac = EXCLUDED.require_hmac,
    replay_window_sec = EXCLUDED.replay_window_sec,
    enabled = EXCLUDED.enabled,
    updated_at = EXCLUDED.updated_at;
