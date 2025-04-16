package server

import (
	"AC-RE-token/handler"

	"github.com/gin-gonic/gin"
)

type Server struct {
	r       *gin.Engine
	handler *handler.Handler
}

func NewServer(handler *handler.Handler, r *gin.Engine) *Server {
	return &Server{
		r:       r,
		handler: handler,
	}
}

func (s *Server) Start(port string) {

	if err := s.r.Run(port); err != nil {
		panic(err)
	}
}
