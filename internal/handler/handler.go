package handler

type Service interface {
	GenerateToken() string
	RefreshToken() string
}

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}
