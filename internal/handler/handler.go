package handler

import (
	"AC-RE-token/internal/models"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Service interface {
	GenerateTokens(userGUID, userIP string) (*models.TokenResponse, error)
	RefreshToken(request models.TokenRequest, userIP string) (*models.TokenResponse, error)
}

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GenerateToken(c *gin.Context) {

	userGUID := c.Param("userGUID")
	if userGUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User GUID is required"})
		return
	}

	ip := c.ClientIP()
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Client IP is required"})
		return
	}

	response, err := h.service.GenerateTokens(userGUID, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) RefreshToken(c *gin.Context) {
	var tokenRequest models.TokenRequest
	if err := c.ShouldBindJSON(&tokenRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	ip := c.ClientIP()
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Client IP is required"})
		return
	}

	newTokens, err := h.service.RefreshToken(tokenRequest, ip)
	if err != nil {
		if errors.Is(err, fmt.Errorf("invalid access token")) || errors.Is(err, fmt.Errorf("invalid refresh token")) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		}
	}

	c.JSON(http.StatusOK, newTokens)
}
