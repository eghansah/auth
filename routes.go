package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/rs/xid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func (s *server) InitRoutes() {
	r := *mux.NewRouter()
	r.HandleFunc(fmt.Sprintf("%s/auth/register", s.cfg.URLPrefix), s.Register()).Name("register")
	r.HandleFunc(fmt.Sprintf("%s/auth/login", s.cfg.URLPrefix), s.Login()).Name("login").Methods("POST", "OPTIONS")
	r.HandleFunc(fmt.Sprintf("%s/auth/request_password_reset", s.cfg.URLPrefix), s.PasswordResetRequestHandler()).Name("password_reset_request").Methods("POST", "OPTIONS")
	r.HandleFunc(fmt.Sprintf("%s/auth/change_password", s.cfg.URLPrefix), s.ChangePasswordHandler()).Name("change_password").Methods("POST", "OPTIONS")
	r.HandleFunc(fmt.Sprintf("%s/auth/csrf", s.cfg.URLPrefix), s.GetCSRFToken()).Name("gencsrf")
	r.HandleFunc(fmt.Sprintf("%s/auth/whoami", s.cfg.URLPrefix), s.Profile()).Name("profile")
	r.HandleFunc(fmt.Sprintf("%s/api/verify_login", s.cfg.URLPrefix), s.GetLoggedInUserDetails())

	r.Use(s.CSRFMiddleware)
	r.Use(s.createRequestIDMiddleware)

	s.router = &r

	credentials := handlers.AllowCredentials()
	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "x-csrf-token"})
	methods := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	origins := handlers.AllowedOrigins(viper.GetStringSlice("CORS_ORIGIN_WHITELIST"))

	// s.svr.Handler = &r
	s.svr.Handler = handlers.CORS(credentials, headers, methods, origins)(&r)
}

func (s *server) createRequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("x-req-id")
		if reqID == "" {
			reqID = xid.New().String()
			r.Header.Add("x-req-id", reqID)
		}

		s.logger.WithFields(logrus.Fields{
			"x-req-id": reqID,
			"endpoint": r.URL.Path,
		}).Info("Received new request")
		next.ServeHTTP(w, r)
	})
}

func (s *server) LoginRequired(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		if reqID == "" {
			reqID = xid.New().String()
			r.Header.Add("x-req-id", reqID)
		}

		requestLogger := s.logger.WithFields(logrus.Fields{
			"request-id":     reqID,
			"Function Name":  "LoginRequired",
			"endpoint":       r.URL.Path,
			"request-method": r.Method,
		})

		requestLogger.Info("Check if sid (session id) cookie exists")
		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid
			requestLogger = requestLogger.WithFields(logrus.Fields{"sid": cookie.Value})
			requestLogger.Info("sid cookie exists. Let's check if session is valid")

			uid, err := s.cache.Get(cookie.Value).Int()
			if err == nil {
				//Session ID is valid
				//Let's fetch user
				requestLogger.Info("Session ID is valid. Let's fetch user")

				user := User{}
				tx := s.db.Model(User{}).Where("id = ?", uid).First(&user)
				if tx.Error != nil {
					requestLogger.WithFields(logrus.Fields{
						"error": tx.Error,
					}).Error("An error occured while fetching user from db")
				} else {
					//User is valid. Redirect
					requestLogger.Info("User is valid. Extending session expiry and proceeding with request . . .")
					s.cache.Expire(cookie.Value, time.Duration(s.cfg.SessionExpiryInSeconds*int(time.Second)))
					h.ServeHTTP(w, r)
					return
				}

			}
		}

		loginurl, err := s.router.Get("login").URL()
		if err != nil {
			requestLogger.WithError(err).Info("URL reversal failed.")
		}
		redirectURL := fmt.Sprintf("%s?next=%s", loginurl, r.URL.Path)
		requestLogger.WithFields(logrus.Fields{"redirect-url": redirectURL}).Info("No valid user login session found. Redirecting to login screen")
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)

	})
}
