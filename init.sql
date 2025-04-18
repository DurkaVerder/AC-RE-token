-- Table for refresh token

CREATE TABLE users (
    id GUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (id, name, email, password) VALUES
("1e2d3c4b-5a6f-7g8h-9i0j-k1l2m3n4o5p6", "Tim", "vrrrr228@gmail.com", "1234");

CREATE TABLE refresh_token (
    id SERIAL PRIMARY KEY,
    user_id GUID NOT NULL,
    token VARCHAR(255) NOT NULL,
    access_tokenId VARCHAR(255) NOT NULL,
    ip_address VARCHAR(255) NOT NULL,
    expired_at TIMESTAMP NOT NULL,
    isRevoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

