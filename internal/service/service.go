package service

import (
	"AC-RE-token/internal/models"
	"AC-RE-token/internal/notification"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	lifeTimeAccessToken  = 15 * time.Minute
	lifeTimeRefreshToken = 7 * 24 * time.Hour
	countWorkers         = 5
)

type DB interface {
	AddRefreshToken(userGUID, jti, refreshTokenHash, userIP string) error
	GetRefreshToken(userGUID, jti string) (string, error)
	GetUserIP(userGUID, jti string) (string, error)
	SetRevoked(userGUID, jti string) error
	GetUserEmail(userID string) (string, error)
}

type Service struct {
	wg *sync.WaitGroup

	db     DB
	notify *notification.EmailNotifier

	userIDChan chan string
}

func NewService(db DB, notify *notification.EmailNotifier, userChan chan string) *Service {
	return &Service{
		wg:         &sync.WaitGroup{},
		db:         db,
		notify:     notify,
		userIDChan: userChan,
	}
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

func (s *Service) RefreshToken(request models.TokenRequest, userIP string) (*models.TokenResponse, error) {

	refreshTokenData, err := s.parseRefreshToken(request.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.parseAccessToken(request.AccessToken)
	if err != nil {
		return nil, err
	}

	ok, err := s.validateAccessWithRefreshToken(accessToken, *refreshTokenData, request.RefreshToken, userIP)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("invalid access token")
	}

	if err := s.db.SetRevoked(refreshTokenData.UserGUID, refreshTokenData.JTI); err != nil {
		return nil, err
	}

	response, err := s.GenerateTokens(refreshTokenData.UserGUID, userIP)
	if err != nil {
		return nil, err
	}

	return response, nil
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
	refreshTokenData, err := s.parseRefreshToken(refreshToken)
	if err != nil {
		return err
	}
	jti := refreshTokenData.JTI
	refreshTokenHash, err := s.bcryptHashRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	if err := s.db.AddRefreshToken(userGUID, jti, refreshTokenHash, userIP); err != nil {
		return err
	}

	return nil
}

func (s *Service) bcryptHashRefreshToken(refreshToken string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
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

func (s *Service) parseRefreshToken(tokenStr string) (*models.RefreshTokenData, error) {
	tokenBytes, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refresh token: %w", err)
	}

	var refreshToken models.RefreshToken
	if err := json.Unmarshal(tokenBytes, &refreshToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	data, err := json.Marshal(refreshToken.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh token data: %w", err)
	}

	mac := hmac.New(sha512.New, []byte(os.Getenv("SUPER-SECRET-KEY-RE")))
	if _, err := mac.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compute HMAC: %w", err)
	}

	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if expectedSignature != refreshToken.Signature {
		return nil, fmt.Errorf("invalid refresh token signature")
	}

	if time.Now().Unix() > refreshToken.Data.Exp {
		return nil, fmt.Errorf("refresh token expired")
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

	ok, err := s.compareHashRefreshToken(refreshTokenForCheckHash, refreshToken.UserGUID, refreshToken.JTI)
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

	t, ok := claims["exp"].(float64)
	if !ok {
		return false, fmt.Errorf("invalid access token expiration time")
	}

	if int64(t) < time.Now().Unix() {
		return false, fmt.Errorf("access token expired")
	}

	if claims["guid"] != refreshToken.UserGUID {
		return false, fmt.Errorf("not equal guid")
	}

	if claims["jti"] != refreshToken.JTI {
		return false, fmt.Errorf("not equal jti")
	}

	userIPFromDB, err := s.db.GetUserIP(refreshToken.UserGUID, refreshToken.JTI)
	if err != nil {
		return false, err
	}

	if userIPFromDB != userIP {
		s.userIDChan <- refreshToken.UserGUID
	}

	return true, nil
}

func (s *Service) compareHashRefreshToken(refreshTokenHash, userGUID, jti string) (bool, error) {
	refreshTokenFromDB, err := s.db.GetRefreshToken(userGUID, jti)
	if err != nil {
		return false, err
	}
	if refreshTokenFromDB == "" {
		return false, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(refreshTokenFromDB), []byte(refreshTokenHash))
	if err != nil {
		return false, nil
	}

	return true, nil
}

func (s *Service) sendEmailWarning(userGUID string) error {

	email, err := s.db.GetUserEmail(userGUID)
	if err != nil {
		return err
	}

	err = s.notify.SendWarning(email, notification.WarningNotifyEmailAnotherIP)
	if err != nil {
		return fmt.Errorf("error send email: %v", err)
	}

	return nil
}

func (s *Service) workerSendEmail() {
	defer s.wg.Done()
	for userID := range s.userIDChan {
		if err := s.sendEmailWarning(userID); err != nil {
			fmt.Printf("error send email: %v\n", err)
		}
	}
}

func (s *Service) StartWorker() {
	for i := 0; i < countWorkers; i++ {
		s.wg.Add(1)
		go s.workerSendEmail()
	}
}
