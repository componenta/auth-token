CREATE TABLE auth_one_time_tokens (
    subject_uuid UUID NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    binding VARCHAR(256) NULL,
    credential_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    used_at TIMESTAMP(6) WITHOUT TIME ZONE NULL,
    PRIMARY KEY (subject_uuid, purpose)
);

CREATE INDEX idx_auth_one_time_tokens_cleanup
    ON auth_one_time_tokens(expires_at, used_at);
