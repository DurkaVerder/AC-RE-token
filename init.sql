-- Table for refresh token

CREATE TABLE users (
    id UUID PRIMARY KEY UNIQUE,
    name VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (id, name, email, password) VALUES
('1e2d3c4b-5a6f-4f8a-9c0d-a1b2c3d4e5f6', 'Tim', 'vrrrr228@gmail.com', '1234');


CREATE TABLE refresh_token (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    isRevoked BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);