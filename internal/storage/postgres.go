package store

import "database/sql"

const (
	GetRefreshTokenQuery = `SELECT token_hash FROM refresh_token WHERE user_id = $1 AND jti = $2 AND isRevoked = false`
	AddRefreshTokenQuery = `INSERT INTO refresh_token (user_id, jti, token_hash, ip_address) VALUES ($1, $2, $3, $4)`
	GetUserIPQuery       = `SELECT ip_address FROM refresh_token WHERE user_id = $1 AND jti = $2 AND isRevoked = false`
	SetRevokedQuery      = `UPDATE refresh_token SET isRevoked = true WHERE user_id = $1 AND jti = $2`
)

type Postgres struct {
	db *sql.DB
}

func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: db}
}

func (p *Postgres) GetRefreshToken(userID, jti string) (string, error) {
	row := p.db.QueryRow(GetRefreshTokenQuery, userID, jti)
	var tokenHash string
	err := row.Scan(&tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return tokenHash, nil
}

func (p *Postgres) AddRefreshToken(userID, jti, tokenHash, ipAddress string) error {
	_, err := p.db.Exec(AddRefreshTokenQuery, userID, jti, tokenHash, ipAddress)
	if err != nil {
		return err
	}
	return nil
}

func (p *Postgres) GetUserIP(userID, jti string) (string, error) {
	row := p.db.QueryRow(GetUserIPQuery, userID, jti)
	var ipAddress string
	err := row.Scan(&ipAddress)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return ipAddress, nil
}

func (p *Postgres) SetRevoked(userID, jti string) error {
	_, err := p.db.Exec(SetRevokedQuery, userID, jti)
	if err != nil {
		return err
	}
	return nil
}
