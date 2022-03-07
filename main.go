package main

import (
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/rs/xid"
	"github.com/spf13/viper"
)

func createService() {
	seviceID := xid.New().String()
	apiKey := uuid.NewString()
	fmt.Printf("\nService ID: %s\nAPI-KEY: %s\n", seviceID, apiKey)
}

func main() {
	viper.AutomaticEnv()

	MANDATORY_ENV_VARS := map[string]string{
		"DEBUG":                 "DEBUG environment variable needs to be TRUE or FALSE. CSRF setting depends on this",
		"CORS_ORIGIN_WHITELIST": "CORS_ORIGIN_WHITELIST needs to be set (eg \"localhost:3000 localhost:2000\")",
		"DBHOST":                "DBHOST environment variable needs to be set",
		"DBUSER":                "DBUSER environment variable needs to be set",
		"DBPASSWD":              "DBPASSWD environment variable needs to be set",
		"DBNAME":                "DBNAME environment variable needs to be set",
		"PORT":                  "PORT environment variable needs to be set",
		"REDIS_SERVER":          "REDIS_SERVER environment variable needs to be set",
		"SENDGRID_API_KEY":      "SENDGRID_API_KEY environment variable needs to be set",
		"SUPPORT_EMAIL":         "SUPPORT_EMAIL environment variable needs to be set",
	}

	//Check if user wants to run some other command
	if len(os.Args) > 1 && os.Args[1] == "generate-ids" {
		createService()
		return
	}

	for k := range MANDATORY_ENV_VARS {
		if !viper.IsSet(k) {
			panic(MANDATORY_ENV_VARS[k])
		}
	}

	s := server{}
	cfg := config{
		Host:                   "127.0.0.1",
		Port:                   viper.GetInt("PORT"),
		RedisServer:            viper.GetString("REDIS_SERVER"),
		SessionExpiryInSeconds: 300,
		CSRFKey:                "32-byte-long-auth-key",
	}

	s.Init(cfg)
	s.Run()
}
