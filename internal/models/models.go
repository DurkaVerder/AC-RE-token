package models

type User struct {
	UserGUID string `json:"user_guid"`
	Email    string `json:"email"`
}

type RefreshTokenFromDB struct {
	UserGUID  string
	TokenHash string
	UserIP    string
	IsRevoked bool
}

type RefreshTokenData struct {
	UserGUID string `json:"user_guid"`
	UserIP   string `json:"user_ip"`
	JTI      string `json:"jti"`
	Exp      int64  `json:"exp"`
}

type RefreshToken struct {
	Data      RefreshTokenData `json:"data"`
	Signature string           `json:"signature"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
