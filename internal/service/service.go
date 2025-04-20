package service

import (
	"AC-RE-token/internal/models"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	lifeTimeAccessToken  = 15 * time.Minute
	lifeTimeRefreshToken = 7 * 24 * time.Hour
)

type DB interface {
	AddRefreshToken(userGUID, userIP, refreshTokenHash string) error
}

type Service struct {
	db DB
}

func NewService(db DB) *Service {
	return &Service{db: db}
}

func (s *Service) GenerateTokens(userGUID, userIP string) (*models.TokenResponse, error) {

	jti := uuid.New().String()
	accessToken, err := s.generateAccessToken(userGUID, userIP, jti)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(userGUID, userIP, jti)
	if err != nil {
		return nil, err
	}

	if err := s.addRefreshTokenToDB(userGUID, userIP, refreshToken); err != nil {
		return nil, err
	}

	return &models.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) generateAccessToken(userGUID, userIP, jti string) (string, error) {

	accessToken, err := s.generateJwtToken(userGUID, userIP, jti)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *Service) generateRefreshToken(userGUID, userIP, jti string) (string, error) {
	refreshTokenData := models.RefreshTokenData{
		UserGUID: userGUID,
		UserIP:   userIP,
		JTI:      jti,
		Exp:      time.Now().Add(lifeTimeRefreshToken).Unix(),
	}

	data, err := json.Marshal(refreshTokenData)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha512.New, []byte(os.Getenv("SUPER-SECRET-KEY-RE")))
	if _, err := mac.Write(data); err != nil {
		return "", err
	}

	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	refreshToken := models.RefreshToken{
		Data:      refreshTokenData,
		Signature: signature,
	}

	refreshTokenBytes, err := json.Marshal(refreshToken)
	if err != nil {
		return "", err
	}
	refreshTokenStr := base64.StdEncoding.EncodeToString(refreshTokenBytes)

	return refreshTokenStr, nil
}

func (s *Service) addRefreshTokenToDB(userGUID, userIP, refreshToken string) error {
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := s.db.AddRefreshToken(userGUID, userIP, string(refreshTokenHash)); err != nil {
		return err
	}

	return nil
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

func (s *Service) sendEmailWarning(userGUID uint64) error {
	// Send an email warning to the user with the given ID
	// This is a placeholder implementation and should be replaced with actual logic
	return nil
}
