CREATE TABLE auth_one_time_tokens (
    subject_uuid TEXT NOT NULL,
    purpose TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT NULL,
    PRIMARY KEY (subject_uuid, purpose)
);

CREATE INDEX auth_one_time_tokens_cleanup
    ON auth_one_time_tokens(expires_at, used_at);
