package notification

import (
	"fmt"
	"net/smtp"
)

const (
	WarningNotifyEmailAnotherIP = "Внимание! Обнаружен вход в вашу учетную запись с другого IP-адреса. Если это не вы, пожалуйста, измените пароль и проверьте безопасность вашей учетной записи."
)

type DB interface {
	GetUserEmail(userGUID string) (string, error)
}

type EmailNotifier struct {
	from     string
	password string
	smtpHost string
	smtpPort string
}

func NewEmailNotifier(from, password, smtpHost, smtpPort string) *EmailNotifier {
	return &EmailNotifier{
		from:     from,
		password: password,
		smtpHost: smtpHost,
		smtpPort: smtpPort,
	}
}

func (e *EmailNotifier) SendWarning(to string, message string) error {

	if to == "" {
		return fmt.Errorf("recipient email is empty")
	}

	auth := smtp.PlainAuth("", e.from, e.password, e.smtpHost)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: Предупреждение о безопасности\r\n\r\n%s", to, message))

	err := smtp.SendMail(e.smtpHost+":"+e.smtpPort, auth, e.from, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("error send email: %v", err)
	}
	return nil
}
