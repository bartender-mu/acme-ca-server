ALTER TABLE challenges ADD COLUMN type TEXT NOT NULL DEFAULT 'http-01' CHECK (type IN ('http-01', 'dns-01'));

DO $$
DECLARE
    con_name TEXT;
BEGIN
    SELECT conname INTO con_name
    FROM pg_constraint
    WHERE conrelid = 'challenges'::regclass
      AND contype = 'u'
      AND conkey = (SELECT array_agg(attnum ORDER BY attnum) FROM pg_attribute WHERE attrelid = 'challenges'::regclass AND attname = 'authz_id');

    IF con_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE challenges DROP CONSTRAINT %I', con_name);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS challenges_authz_id_idx ON challenges(authz_id);
