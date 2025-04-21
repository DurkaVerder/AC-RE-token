package service

import (
	"AC-RE-token/internal/models"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	GetRefreshToken(userGUID string) (string, error)
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

func (s *Service) RefreshToken(request models.TokenRequest, userIP string) (models.TokenResponse, error) {

	refreshTokenData, err := s.parseRefreshToken(request.RefreshToken)
	if err != nil {
		return models.TokenResponse{}, err
	}

	accessToken, err := s.parseAccessToken(request.AccessToken)
	if err != nil {
		return models.TokenResponse{}, err
	}

	ok, err := s.validateAccessWithRefreshToken(accessToken, *refreshTokenData, request.RefreshToken, userIP)
	if err != nil {
		return models.TokenResponse{}, err
	}

	if !ok {
		return models.TokenResponse{}, fmt.Errorf("invalid access token")
	}

	response, err := s.GenerateTokens(refreshTokenData.UserGUID, userIP)
	if err != nil {
		return models.TokenResponse{}, err
	}

	return *response, nil
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

func (s *Service) parseRefreshToken(tokenStr string) (*models.RefreshTokenData, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}

	var refreshToken models.RefreshToken
	if err := json.Unmarshal(tokenBytes, &refreshToken); err != nil {
		return nil, err
	}

	return &refreshToken.Data, nil
}

func (s *Service) parseAccessToken(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SUPER-SECRET-KEY")), nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *Service) validateAccessWithRefreshToken(accessToken *jwt.Token, refreshToken models.RefreshTokenData, refreshTokenForCheckHash string, userIP string) (bool, error) {

	if !accessToken.Valid {
		return false, fmt.Errorf("invalid access token")
	}

	ok, err := s.compareHashsRefreshToken(refreshTokenForCheckHash, refreshToken.UserGUID)
	if err != nil {
		return false, err
	}

	if !ok {
		return false, fmt.Errorf("invalid refresh token")
	}

	claims, ok := accessToken.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid access token claims")
	}

	if claims["guid"] != refreshToken.UserGUID {
		return false, fmt.Errorf("not equal guid")
	}

	if claims["jti"] != refreshToken.JTI {
		return false, fmt.Errorf("not equal jti")
	}

	return false, nil
}

func (s *Service) compareHashsRefreshToken(refreshTokenHash, userGUID string) (bool, error) {
	refershTokenFromDB, err := s.db.GetRefreshToken(userGUID)
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(refershTokenFromDB), []byte(refreshTokenHash))
	if err != nil {
		return false, err
	}

	return true, nil
}
