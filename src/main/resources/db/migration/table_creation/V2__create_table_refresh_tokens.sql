    CREATE TABLE refresh_tokens (
                                    id SERIAL PRIMARY KEY,
                                    user_id INT NOT NULL,
                                    token_hash VARCHAR(255) NOT NULL UNIQUE,
                                    expires_at TIMESTAMP NOT NULL,
                                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                    revoked_at TIMESTAMP,
                                    replaced_by INTEGER,
                                    device_info VARCHAR(255),

                                    CONSTRAINT fk_refresh_tokens_user_id
                                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
    CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
    CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
