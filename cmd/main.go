package main

import (
	"AC-RE-token/internal/handler"
	"AC-RE-token/internal/notification"
	"AC-RE-token/internal/server"
	"AC-RE-token/internal/service"
	"AC-RE-token/internal/storage"
	"os"

	"github.com/gin-gonic/gin"
)

const (
	driver = "postgres"
)

func main() {
	db := storage.Connect(driver, os.Getenv("DB_URL"))
	defer db.Close()

	postgres := storage.NewPostgres(db)

	notify := notification.NewEmailNotifier(os.Getenv("MAIL"), os.Getenv("EMAIL_PASSWORD"), os.Getenv("SMTP_HOST"), os.Getenv("SMTP_PORT"))

	userIDChan := make(chan string)

	authService := service.NewService(postgres, notify, userIDChan)

	authService.StartWorker()

	handlers := handler.NewHandler(authService)

	r := gin.Default()
	r.Use(gin.Logger())

	serv := server.NewServer(handlers, r)

	serv.Start(os.Getenv("PORT"))

}
