package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Service interface {
	GenerateTokens(userGUID, userIP string) (string, string, error)
	RefreshToken() string
}

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GetTokens(c *gin.Context) {

	userGUID := c.Param("userGUID")

	ip := c.ClientIP()

	accessToken, refreshToken, err := h.service.GenerateTokens(userGUID, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
