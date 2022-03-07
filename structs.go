package main

import (
	"database/sql"
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ID               int64
	SID              string `gorm:"uniqueIndex,size:255"`
	GUID             string `gorm:"uniqueIndex,size:255" json:"global_id"`
	Username         string `gorm:"uniqueIndex,size:255"`
	Firstname        string `json:"firstname"`
	Lastname         string `json:"lastname"`
	Email            string `gorm:"uniqueIndex,size:255" json:"email"`
	Password         []byte
	Active           bool
	EnableTOTP       bool
	TOTPSecret       string
	TOTPSecretLength int64
}

type APIUserResponse struct {
	User
	Status        string `json:"status"`
	ErrMsg        string `json:"err_msg"`
	RedirectToURL string `json:"redirect_to"`
}

type OneTimeUserAuthToken struct {
	ApiKey       string `json:"apikey"`
	GlobalUserID string `json:"global_user_id"`
}

type Service struct {
	gorm.Model
	ID               int64
	ServiceID        string         `gorm:"uniqueIndex,size:255"`
	Domain           sql.NullString `gorm:"uniqueIndex,size:255"`
	LoginRedirectURL string
	CallbackURL      sql.NullString
	SecretKey        string
	APIKey           string
	Enabled          bool
}

type PasswordResetRequest struct {
	gorm.Model
	ResetCode string `gorm:"uniqueIndex,size:255"`
	Email     string
	ExpiresOn time.Time
	Active    bool
	Status    sql.NullString
}

func (s *server) MigrateDB() {
	s.db.AutoMigrate(User{})
	s.db.AutoMigrate(Service{})
	s.db.AutoMigrate(PasswordResetRequest{})

	// apikey, err := GenerateRandomStringURLSafe(64)
	// if err != nil {
	// 	log.Fatalf("Could not generate apikey: %s", err)
	// }

	// secret, err := GenerateRandomStringURLSafe(64)
	// if err != nil {
	// 	log.Fatalf("Could not generate secret: %s", err)
	// }

	// serviceID := xid.New().String()
	// s.db.Create(&Service{
	// 	ServiceID:        serviceID,
	// 	LoginRedirectURL: "http://127.0.0.1",
	// 	APIKey:           apikey,
	// 	SecretKey:        secret,
	// 	Enabled:          true,
	// })
}
