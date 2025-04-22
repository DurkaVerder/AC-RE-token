package server

import (
	"github.com/gin-gonic/gin"
)

type Handler interface {
	GenerateToken(c *gin.Context)
	RefreshToken(c *gin.Context)
}

type Server struct {
	r       *gin.Engine
	handler Handler
}

func NewServer(handler Handler, r *gin.Engine) *Server {
	return &Server{
		r:       r,
		handler: handler,
	}
}

func (s *Server) initRoutes() {
	s.r.GET("/api/v1/token/:userGUID", s.handler.GenerateToken)
	s.r.POST("/api/v1/refresh-token", s.handler.RefreshToken)
}

func (s *Server) Start(port string) {

	s.initRoutes()

	if err := s.r.Run(port); err != nil {
		panic(err)
	}
}
