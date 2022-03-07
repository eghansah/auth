package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/rs/xid"
	"github.com/sendgrid/rest"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type config struct {
	Host                   string
	Port                   int
	URLPrefix              string
	RedisServer            string
	SessionExpiryInSeconds int
	CSRFKey                string
	EnableTOTP             bool
	LogLevel               string
}

type server struct {
	db             *gorm.DB
	svr            *http.Server
	cfg            config
	router         *mux.Router
	cache          *redis.Client
	CSRFMiddleware func(http.Handler) http.Handler
	logger         *logrus.Logger
}

func (s *server) sendPasswordResetEmail(r *http.Request, to *mail.Email,
	resetReq PasswordResetRequest) (*rest.Response, error) {
	from := mail.NewEmail("support", viper.GetString("SUPPORT_EMAIL"))
	subject := "Password Reset"
	passwordResetLink := fmt.Sprintf("https://%s/change-password/%s", r.Host, resetReq.ResetCode)
	plainTextContent := fmt.Sprintf(`Dear %s,
	To complete your password reset, kindly copy and paste the link below in your browser. 
	Kindly note that the link expires in 60 minutes.
	%s
	
	Please ignore this email if you did not request for the reset.
	
	
	Thank you`, to.Name, passwordResetLink)

	var buf bytes.Buffer
	data := struct {
		PasswordResetLink string
	}{
		PasswordResetLink: passwordResetLink,
	}
	tmpl := template.Must(template.ParseFiles("html/forgot_password_email.html"))
	tmpl.Execute(&buf, data)
	htmlContent := buf.String()
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(os.Getenv("SENDGRID_API_KEY"))

	return client.Send(message)
}

func (s *server) getUser(reqID, sessionID string) *User {

	pc, _, _, _ := runtime.Caller(1)
	details := runtime.FuncForPC(pc)

	requestLogger := s.logger.WithFields(logrus.Fields{
		"Function Name": "getUser",
		"Called From":   details.Name(),
		"request-id":    reqID,
		"session-id":    sessionID,
	})

	//sid cookie exists. Let's check if session is valid
	requestLogger.Info("Let's check if session is valid")

	uid, err := s.cache.Get(sessionID).Int()
	if err != nil {
		requestLogger.Info("session-id is not valid. return")
		return nil
	}

	//Session ID is valid
	//Let's fetch user
	requestLogger.Info("Session ID is valid. Let's fetch user")

	user := User{}
	tx := s.db.Model(User{}).Where("id = ?", uid).First(&user)
	if tx.Error != nil {
		requestLogger.WithFields(logrus.Fields{
			"error": tx.Error,
		}).Error("An error occured while fetching user from db")
		return nil
	}

	requestLogger.Info("User found. Returning user")
	return &user
}

func (s *server) Init(c config) {
	s.cfg = c

	s.logger = logrus.New()
	s.logger.SetFormatter(&logrus.JSONFormatter{})
	s.logger.SetLevel(logrus.DebugLevel)

	csrfSecure := true
	if viper.GetBool("DEBUG") {
		csrfSecure = false
	}
	_ = csrfSecure
	s.CSRFMiddleware = csrf.Protect([]byte(s.cfg.CSRFKey),
		csrf.Secure(true),
		csrf.Path("/auth"),
		csrf.TrustedOrigins(viper.GetStringSlice("CORS_ORIGIN_WHITELIST")),
		// instruct the browser to never send cookies during cross site requests
		csrf.SameSite(csrf.SameSiteNoneMode),
	)

	// w.Header().Set("Vary", "Origin")
	// w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	// w.Header().Set("Access-Control-Allow-Credentials", "true")
	// w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	// w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

	s.svr = &http.Server{
		Addr: fmt.Sprintf("%s:%d", c.Host, c.Port),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
	}

	s.cache = redis.NewClient(&redis.Options{
		Addr:     s.cfg.RedisServer,
		Password: "",
		DB:       0,
	})

	resp := s.cache.Ping()
	if resp.Err() != nil {
		s.logger.WithError(resp.Err()).Error("Redis connection returned an error. Aborting")
		log.Fatal("Could not connect to redis.")
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		viper.GetString("DBUSER"),
		viper.GetString("DBPASSWD"),
		viper.GetString("DBHOST"),
		viper.GetInt("DBPORT"),
		viper.GetString("DBNAME"))
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatalf("Unable to initialize db connection: %s\n", err.Error())
	}

	s.db = db

	s.MigrateDB()
	s.InitRoutes()

}

func (s *server) Run() {
	mode := "PRODUCTION"
	if viper.GetBool("DEBUG") {
		mode = "DEV"
	}
	log.Printf("Server running in %s mode at http://%s:%d/\n\n", mode, s.cfg.Host, s.cfg.Port)
	log.Printf("\tCORS WHITELISTED ORIGINS: %v\n", viper.GetStringSlice("CORS_ORIGIN_WHITELIST"))
	s.svr.ListenAndServe()
}

func (s *server) Register() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		tmpl := template.Must(template.ParseFiles("html/register.html"))

		if cookie, err := r.Cookie("sid"); err == nil {
			//sid cookie exists. Let's check if session is valid
			uid, err := s.cache.Get(cookie.Value).Int()
			if err == nil {
				//Session ID is valid
				//Let's fetch user
				user := User{}
				tx := s.db.Model(User{}).Where("id = ?", uid).First(&user)
				if tx.Error != nil {
					log.Println(tx.Error)
				} else {
					//User is valid. Redirect
					s.redirectAfterSuccessfulLogin(w, r, cookie, &user)
					return
				}

			}
		}

		if r.Method == "GET" {
			tmpl.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
			})
			return
		}

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = ioutil.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = ioutil.NopCloser(bytes.NewBuffer(rawReqBody))

		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		//Check for required params
		required := []string{"email", "password"}
		for _, rq := range required {
			if _, ok := reqMap[rq]; !ok {
				tmpl.Execute(w, map[string]interface{}{
					csrf.TemplateTag: csrf.TemplateField(r),
					"msg":            fmt.Sprintf("Required parameter missing: %s", rq),
				})
				return
			}
		}

		passwd, _ := bcrypt.GenerateFromPassword([]byte(reqMap["password"]), 14)
		u := &User{
			Firstname: reqMap["firstname"],
			Lastname:  reqMap["lastname"],
			Email:     reqMap["email"],
			Username:  reqMap["email"],
			Password:  passwd,
			SID:       xid.New().String(),
			GUID:      uuid.New().String(),
		}

		tx := s.db.Create(u)
		if tx.Error != nil {
			log.Println(tx.Error)
			tmpl.Execute(w, map[string]interface{}{
				csrf.TemplateTag: csrf.TemplateField(r),
				"msg":            "Could not register user",
			})
			return
		}

		w.Write([]byte("User successfully registered"))
	}
}

func (s *server) GetCSRFToken() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		fmt.Fprint(w, csrf.Token(r))
	}
}

func (s *server) Login() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.WithFields(logrus.Fields{
			"request-id":     reqID,
			"handler":        "Login",
			"Function Name":  "Login",
			"endpoint":       r.URL.Path,
			"request-method": r.Method,
		})

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
					requestLogger.Info("User is valid. Calling redirectAfterSuccessfulLogin . . .")
					s.redirectAfterSuccessfulLogin(w, r, cookie, &user)
					return
				}

			}
		}

		requestLogger.Info("Either no sid cookie was found or sid was not found in cache. Proceeding")

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = ioutil.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = ioutil.NopCloser(bytes.NewBuffer(rawReqBody))

		requestLogger.Info("Parsing request body")
		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		// vars := mux.Vars(r)

		//Check for required params
		required := []string{"username", "password"}
		for _, r := range required {
			if _, ok := reqMap[r]; !ok {
				requestLogger.Infof("Required parameter missing: %s", r)

				u := APIUserResponse{}
				u.Status = "error"
				u.ErrMsg = fmt.Sprintf("Required parameter missing: %s", r)
				js, _ := json.Marshal(u)

				w.WriteHeader(http.StatusOK)
				w.Write(js)
				return
			}
		}

		user := User{}
		tx := s.db.Model(User{}).Where("email = ?", strings.ToLower(reqMap["username"])).First(&user)
		if tx.Error != nil {
			requestLogger.WithError(tx.Error).Info("An error occured while reading from DB. Treating this as user does not exist.")
			log.Println(tx.Error)
		}

		if user.ID == 0 {
			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "Incorrect username or password"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		requestLogger.Info("User found. Checking for password")
		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(reqMap["password"])); err != nil {
			requestLogger.Info("Password does not match stored password. Aborting login request.")
			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "Incorrect username or password"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		//Login succesful. Let's generate session id
		requestLogger.Info("Login succesful. Let's generate session id")

		sessionID := xid.New()
		requestLogger = requestLogger.WithFields(logrus.Fields{"sid": sessionID})

		requestLogger.Info("Saving session id")
		s.cache.Set(sessionID.String(), user.ID, time.Duration(s.cfg.SessionExpiryInSeconds*int(time.Second)))

		c := http.Cookie{
			Name:     "sid",
			Value:    sessionID.String(),
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}

		requestLogger.Info("Extending session expiry")
		//Extend session expiry
		s.cache.Expire(c.Value, time.Duration(s.cfg.SessionExpiryInSeconds*int(time.Second)))
		http.SetCookie(w, &c)

		qs := r.URL.Query()

		requestLogger.Info("checking for presence of service_id ")
		if _, ok := qs["service"]; ok {
			requestLogger.Info("service_id provided. Calling redirectAfterSuccessfulLogin to redirect to service_id. . .")
			s.redirectAfterSuccessfulLogin(w, r, &c, &user)
			return
		}

		requestLogger.Info("redirect user to profile page")
		profileURL, err := s.router.Get("profile").URL()
		if err != nil {
			requestLogger.WithError(err).Info("Profile URL reversal failed.")
		}

		// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
		if err != nil {
			requestLogger.WithError(err).Info("Profile URL reversal failed.")
		}

		// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
		ur := APIUserResponse{}
		ur.Status = "redirect_internal"
		ur.RedirectToURL = profileURL.Path
		js, _ := json.Marshal(ur)

		w.WriteHeader(http.StatusOK)
		w.Write(js)

	}
}

func (s *server) redirectAfterSuccessfulLogin(w http.ResponseWriter, r *http.Request, cookie *http.Cookie, u *User) {

	pc, _, _, _ := runtime.Caller(1)
	details := runtime.FuncForPC(pc)

	requestLogger := s.logger.WithFields(logrus.Fields{
		"Function Name": "redirectAfterSuccessfulLogin",
		"Called From":   details.Name(),
		"endpoint":      r.URL.Path,
	})

	qs := r.URL.Query()

	requestLogger.Info("checking for service id ")
	if _, ok := qs["service"]; ok {
		service := Service{}
		tx := s.db.Model(Service{}).Where("service_id = ?", qs["service"][0]).First(&service)
		if tx.Error != nil {
			log.Println(tx.Error)
			requestLogger.WithError(tx.Error).Info("Error occured while fetching service with the specified service_id")

			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "Invalid App"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		//Save a short-lived auth token in cache
		requestLogger.Info("Crearting a short-lived auth token in cache")
		tk := xid.New().String()
		tkValue := OneTimeUserAuthToken{}
		tkValue.ApiKey = service.APIKey
		tkValue.GlobalUserID = u.GUID

		tkVal, _ := json.Marshal(tkValue)

		requestLogger.Info("saving short live auth token to redis cache")
		s.cache.Set(tk, string(tkVal), 0)
		s.cache.Expire(tk, 60*time.Second)

		requestLogger.WithFields(logrus.Fields{
			"target-url":       service.LoginRedirectURL,
			"http-status-code": http.StatusSeeOther,
		}).Info("Redirecting request")

		u := APIUserResponse{}
		u.Status = "redirect_external"
		u.RedirectToURL = fmt.Sprintf("%s?tk=%s", service.LoginRedirectURL, tk)
		js, _ := json.Marshal(u)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
		return
	}

	requestLogger.Info("redirect user to profile page")
	profileURL, err := s.router.Get("profile").URL()
	if err != nil {
		requestLogger.WithError(err).Info("Profile URL reversal failed.")
	}

	// http.Redirect(w, r, profileURL.Path, http.StatusSeeOther)
	ur := APIUserResponse{}
	ur.Status = "redirect_internal"
	ur.RedirectToURL = profileURL.Path
	js, _ := json.Marshal(ur)

	w.WriteHeader(http.StatusOK)
	w.Write(js)

}

func (s *server) GetLoggedInUserDetails() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// pc, _, _, _ := runtime.Caller(1)
		// details := runtime.FuncForPC(pc)

		// requestLogger := s.logger.WithFields(logrus.Fields{
		// 	"Function Name": "GetLoggedInUserDetails",
		// 	"Called From":   details.Name(),
		// 	"endpoint":      r.URL.Path,
		// })

		u := APIUserResponse{}

		reqApiKey := r.Header.Get("X-API-KEY")
		if reqApiKey == "" {
			//API-KEY was not provided
			u.Status = "error"
			u.ErrMsg = "API Key not provided"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		//Checking for validity of API-KEY
		thirdPartyService := Service{}
		tx := s.db.Model(Service{}).Where("enabled=1 and api_key = ?", reqApiKey).First(&thirdPartyService)
		if tx.Error != nil {
			log.Println(tx.Error)
			u.Status = "error"
			u.ErrMsg = "Could not find any active service using the API Key provided"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusNotFound)
			w.Write(js)
			return
		}

		qs := r.URL.Query()
		if _, ok := qs["tk"]; !ok {
			//One time user token was not provided
			u.Status = "error"
			u.ErrMsg = "One time user auth token not provided"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		tk, err := s.cache.Get(qs["tk"][0]).Bytes()
		if err != nil {
			//Token is not in cache
			u.Status = "error"
			u.ErrMsg = "Could not find the specified session"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		token := OneTimeUserAuthToken{}
		err = json.Unmarshal(tk, &token)
		if err != nil {
			//Could not parse token
			u.Status = "error"
			u.ErrMsg = "Auth token is corrupt"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		if reqApiKey != token.ApiKey {
			//Token is not in cache
			u.Status = "error"
			u.ErrMsg = "Unauthorized access to session"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusUnauthorized)
			w.Write(js)
			return
		}

		usr := User{}
		tx = s.db.Model(User{}).Where("active=1 and guid = ?", token.GlobalUserID).First(&usr)
		if tx.Error != nil {
			log.Println(tx.Error)
			u.Status = "error"
			u.ErrMsg = "Could not find active user with this ID"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusNotFound)
			w.Write(js)
			return
		}

		u = APIUserResponse{
			Status: "ok",
		}
		u.Firstname = usr.Firstname
		u.Lastname = usr.Lastname
		u.Email = usr.Email
		u.GUID = usr.GUID
		u.Active = usr.Active

		js, _ := json.Marshal(u)
		w.WriteHeader(http.StatusOK)
		w.Write(js)

	}
}

func (s *server) Profile() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.WithFields(logrus.Fields{
			"request-id":     reqID,
			"handler":        "Profile",
			"Function Name":  "Profile",
			"endpoint":       r.URL.Path,
			"request-method": r.Method,
		})

		requestLogger.Info("Checking if cookie exists")
		cookie, err := r.Cookie("sid")
		if err != nil {
			requestLogger.Info("could not fetch cookie. panic")
			u := APIUserResponse{}
			u.Status = "no_active_user"
			u.ErrMsg = "No cookie found"
			js, err := json.Marshal(u)

			if err != nil {
				requestLogger.Error("Error occured while marshalling response object")
			}

			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}

		requestLogger.Info("Fetching user")
		usr := s.getUser(reqID, cookie.Value)
		if usr == nil {
			requestLogger.Info("could not fetch user. panic")
			u := APIUserResponse{}
			u.Status = "no_active_user"
			u.ErrMsg = "Could not find active user with this ID"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		u := APIUserResponse{
			Status: "ok",
		}
		u.Firstname = usr.Firstname
		u.Lastname = usr.Lastname
		u.Email = usr.Email
		u.GUID = usr.GUID
		u.Active = usr.Active

		qs := r.URL.Query()
		if _, ok := qs["service"]; ok {
			//Service parameter was provided.
			//If valid, add redirect-url so auth frontend will redirect
			thirdPartyService := Service{}
			tx := s.db.Model(Service{}).Where("enabled=1 and service_id = ?", qs["service"][0]).First(&thirdPartyService)
			if tx.Error == nil {
				//Service successfully fetched from DB
				redirectTokenObj := OneTimeUserAuthToken{
					ApiKey:       thirdPartyService.APIKey,
					GlobalUserID: u.GUID,
				}
				js, _ := json.Marshal(redirectTokenObj)

				redirectToken := fmt.Sprintf("rdtk%s", xid.New().String())
				results := s.cache.Set(redirectToken, string(js), time.Second*30)
				if results.Err() != nil {
					requestLogger.WithFields(logrus.Fields{
						"error": results.Err(),
					}).Error("Unable to save redirect token in cache")
				}

				rawRedirectURL := thirdPartyService.LoginRedirectURL
				redirectURLObj, err := url.Parse(rawRedirectURL)
				if err != nil {
					requestLogger.WithFields(logrus.Fields{
						"error":        err,
						"redirect-url": rawRedirectURL,
					}).Error("Could not parse redirect URL")
				} else {
					q := redirectURLObj.Query()
					q.Set("tk", redirectToken)
					redirectURLObj.RawQuery = q.Encode()
					u.RedirectToURL = fmt.Sprint(redirectURLObj)
					u.Status = "reditect_external"
				}
			}
		}

		js, _ := json.Marshal(u)
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	}
}

func (s *server) PasswordResetRequestHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.WithFields(logrus.Fields{
			"request-id":     reqID,
			"handler":        "PasswordResetRequestHandler",
			"Function Name":  "PasswordResetRequestHandler",
			"endpoint":       r.URL.Path,
			"request-method": r.Method,
		})

		u := APIUserResponse{
			Status: "ok",
		}

		requestLogger.Info("Extracting request parameters . . .")
		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = ioutil.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = ioutil.NopCloser(bytes.NewBuffer(rawReqBody))

		requestLogger.Info("Parsing request body")
		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		email := ""
		var ok bool
		if email, ok = reqMap["email"]; !ok {
			requestLogger.Info("Required parameter missing: email")

			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "Required parameter missing: email"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		requestLogger.Info("Fetching user")
		user := User{}
		if result := s.db.Where("active = true and email = ?", email).First(&user); result.Error != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": result.Error,
			}).Info("Failing silently as no active user was found")
			u := APIUserResponse{}
			u.Status = "ok"
			u.ErrMsg = ""
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		requestLogger.Info("Creating password request entry")
		reqCode, err := uuid.NewUUID()
		if err != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": err,
			}).Error("UUID code generation returned an error")
			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "unexpected error"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		passwdResetReq := &PasswordResetRequest{
			ResetCode: reqCode.String(),
			Email:     email,
			Active:    true,
			ExpiresOn: time.Now().Local().Add(time.Hour*time.Duration(1) +
				time.Minute*time.Duration(0) +
				time.Second*time.Duration(0)),
		}

		result := s.db.Debug().Model(PasswordResetRequest{}).Where("email = ? and active = true", email).Updates(
			map[string]interface{}{
				"Active": false,
				"status": "replaced_by_new_request",
			})
		if result.Error != nil {
			//Could not invalidate previous reset requests.
			requestLogger.WithFields(logrus.Fields{
				"error": result.Error,
			}).Error("Could not disable previous reset requests")
			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "unexpected error"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		tx := s.db.Create(passwdResetReq)
		if tx.Error != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": tx.Error,
			}).Error("An unexpected error occured while saving password reset request to db.")
			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "unexpected error"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		//Password request saved successfully. Let's fire email
		to := mail.NewEmail(fmt.Sprintf("%s %s", user.Firstname, user.Lastname), passwdResetReq.Email)
		response, err := s.sendPasswordResetEmail(r, to, *passwdResetReq)
		if err != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": err,
			}).Error("An unexpected error occured while sending email.")
			u := APIUserResponse{}
			u.Status = "error"
			u.ErrMsg = "unexpected error"
			js, _ := json.Marshal(u)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		requestLogger.WithFields(logrus.Fields{
			"Response.StatusCode": response.StatusCode,
			"Response.Headers":    response.Headers,
			"Response.Body":       response.Body,
			"Response":            response,
		}).Info("Email sent successfully")

		js, _ := json.Marshal(u)
		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}

func (s *server) ChangePasswordHandler() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("x-req-id")
		requestLogger := s.logger.WithFields(logrus.Fields{
			"request-id":     reqID,
			"handler":        "PasswordResetRequestHandler",
			"Function Name":  "PasswordResetRequestHandler",
			"endpoint":       r.URL.Path,
			"request-method": r.Method,
		})

		reqMap := make(map[string]string)

		// Try to decode the request body into the struct. If there is an error,
		// try to populate struct from POST or GET params.
		// Read the content
		var rawReqBody []byte
		if r.Body != nil {
			rawReqBody, _ = ioutil.ReadAll(r.Body)
			r.Body.Close()
		} // Restore the io.ReadCloser to its original state
		r.Body = ioutil.NopCloser(bytes.NewBuffer(rawReqBody))

		err := json.Unmarshal([]byte(rawReqBody), &reqMap)
		if err != nil {
			r.ParseForm()

			for key, value := range r.Form {
				reqMap[key] = value[0]
			}
		}

		//Check for required params
		required := []string{"reset_code", "password"}
		for _, rq := range required {
			if _, ok := reqMap[rq]; !ok {
				requestLogger.Infof("Mandatory parameter not found: %s", rq)
				resp := APIUserResponse{}
				resp.Status = "error"
				resp.ErrMsg = "required parameters missing"
				js, _ := json.Marshal(resp)

				w.WriteHeader(http.StatusOK)
				w.Write(js)
				return
			}
		}

		// Get active reset request associated with reset_code
		resetReqObj := PasswordResetRequest{}
		result := s.db.Debug().Where("reset_code=? and active=true and expires_on > now()",
			reqMap["reset_code"]).First(&resetReqObj)
		if result.Error != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": result.Error}).Info("Error occured while fetching password_reset_request from db")
			resp := APIUserResponse{}
			resp.Status = "no_pending_request_found"
			resp.ErrMsg = "Could not find any outstanding password reset request with the details provided"
			js, _ := json.Marshal(resp)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		//Get user associated with password request
		u := User{}
		result = s.db.Model(User{}).Where("email = ?", resetReqObj.Email).First(&u)
		if result.Error != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": result.Error}).Info("Error occured while fetching user from db")
			resp := APIUserResponse{}
			resp.Status = "no_matching_user_found"
			resp.ErrMsg = "Could not find any active user with outstanding password reset request using the details provided"
			js, _ := json.Marshal(resp)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		passwd, _ := bcrypt.GenerateFromPassword([]byte(reqMap["password"]), 14)
		result = s.db.Debug().Model(User{}).Where("email = ? and active = true", resetReqObj.Email).Updates(
			map[string]interface{}{
				"password": passwd})
		if result.Error != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": result.Error}).Info("Error occured while updating user password in db")
			resp := APIUserResponse{}
			resp.Status = "password_change_failed"
			resp.ErrMsg = "Could not update user password"
			js, _ := json.Marshal(resp)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		//Disable the password reset request
		result = s.db.Debug().Model(PasswordResetRequest{}).Where("reset_code=? ",
			reqMap["reset_code"]).Updates(map[string]interface{}{
			"active": false,
			"status": "completed",
		})
		if result.Error != nil {
			requestLogger.WithFields(logrus.Fields{
				"error": result.Error}).Info("Error occured while disabling password ")
			resp := APIUserResponse{}
			resp.Status = "error"
			resp.ErrMsg = "unexpected error"
			js, _ := json.Marshal(resp)

			w.WriteHeader(http.StatusOK)
			w.Write(js)
			return
		}

		resp := APIUserResponse{}
		resp.Status = "ok"
		resp.ErrMsg = "Password Changed Successfully"
		js, _ := json.Marshal(resp)

		w.WriteHeader(http.StatusOK)
		w.Write(js)
	}
}
