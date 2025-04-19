package service

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

const (
	lifeTimeAccessToken = 15 * time.Minute
)

type DB interface {
}

type Service struct {
	db DB
}

func NewService(db DB) *Service {
	return &Service{db: db}
}

func (s *Service) GenerateTokens(userGUID, userIP string) (string, string, error) {

	jti := uuid.New().String()
	accessToken, err := s.generateAccessToken(userGUID, userIP, jti)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.generateRefreshToken(userGUID, userIP, jti)
	if err != nil {
		return "", "", err
	}

	// TODO: write check and add refresh token to db

	return accessToken, refreshToken, nil
}

func (s *Service) generateAccessToken(userGUID, userIP, jti string) (string, error) {

	accessToken, err := s.generateJwtToken(userGUID, userIP, jti)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *Service) generateRefreshToken(userGUID, userIP, jti string) (string, error) {
	// Generate a new refresh token for the user with the given GUID
	// This is a placeholder implementation and should be replaced with actual logic
	return "new_refresh_token", nil
}

func (s *Service) generateJwtToken(userGUID, userIP, jti string) (string, error) {

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"guid": userGUID,
		"ip":   userIP,
		"jti":  jti,
		"exp":  time.Now().Add(lifeTimeAccessToken).Unix(),
	}).SignedString([]byte(os.Getenv("SUPER-SECRET-KEY")))
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *Service) SendEmailWarning(userGUID uint64) error {
	// Send an email warning to the user with the given ID
	// This is a placeholder implementation and should be replaced with actual logic
	return nil
}
