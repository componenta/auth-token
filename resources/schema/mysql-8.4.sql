CREATE TABLE auth_one_time_tokens (
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    purpose VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6) NULL,
    PRIMARY KEY (subject_uuid, purpose),
    INDEX idx_auth_one_time_tokens_cleanup (expires_at, used_at)
) ENGINE=InnoDB;
