package handlers

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"login/jwt"
	"login/oauth"
	"login/structs"
	"login/utils"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	EMAIL_VERIFICATION string = "Email Verification"
	CONTENT_TYPE       string = "application/json"
)

var (
	HASH_COST int
)

var (
	ErrUserNotExists     = errors.New("user not exists")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrWrongPayload      = errors.New("wrong payload")
	ErrNotAllowed        = errors.New("access not allowed")
	ErrPasswordNotSet    = errors.New("password not set")
	ErrShortPassword     = errors.New("password must have minimum length of 8")
)

func SendEmail(postgres *sql.DB, config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		var email = r.URL.Query().Get("email")
		var template = r.URL.Query().Get("template")
		var redirectURL = r.URL.Query().Get("redirect")
		var allowed = true
		var err error = nil

		switch template {

		case "1":
			rows, err := postgres.Query(`
				SELECT * FROM users WHERE email = $1 AND password IS NOT NULL AND salt IS NOT NULL AND deleted_at IS NULL
			`, &email)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			defer rows.Close()
			if rows.Next() {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrUserAlreadyExists.Error())
				return
			}

			allowed, err = utils.IsAllowed(postgres, config)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			if !allowed {
				_, err = postgres.Exec(`
					INSERT INTO not_allowed_emails (email) VALUES ($1)
				`, &email)
				if err != nil {
					log.Default().Print(err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
					return
				}

				template = "ASV_0007"
				break
			}

			template = "ASV_0002"

		case "2":
			template = "ASV_0003"

		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var sendEmailRequest map[string]any = make(map[string]any)
		sendEmailRequest["to"] = email
		sendEmailRequest["from"] = config.Sender
		sendEmailRequest["subject"] = EMAIL_VERIFICATION

		if allowed {
			token, err := jwt.GetEmailTokenString(email, redirectURL, config.JWTKey)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			sendEmailRequest["tags"] = map[string]any{"link1": config.RedirectURL + fmt.Sprintf("?code=%s", (*token))}
		}
		sendEmailRequest["replyTo"] = config.ReplyTo

		bytesData, err := json.Marshal(&sendEmailRequest)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		request, err := http.NewRequest(http.MethodPost, config.EmailSubSystemURL, bytes.NewBuffer(bytesData))
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		request.Header.Set("Content-Type", CONTENT_TYPE)
		request.Header.Set("X-Template-ID", template)
		request.Header.Set("X-Auth-Token", config.EmailAuthToken)

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		defer response.Body.Close()

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"success\":true}")
	}
}

func VerifyUser(postgres *sql.DB, config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		var userGenericDTO structs.UserGenericDTO

		err := json.NewDecoder(r.Body).Decode(&userGenericDTO)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		if userGenericDTO.EmailJWT == nil || userGenericDTO.Password == nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrWrongPayload.Error())
			return
		}

		if len(*userGenericDTO.Password) < 8 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrShortPassword.Error())
			return
		}

		claims, err := jwt.VerifyEmailTokenAndReturnClaims((*userGenericDTO.EmailJWT), config.JWTKey)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		var redirectURL string
		if len(claims.RedirectURL) > 0 {
			bytes, err := hex.DecodeString(claims.RedirectURL)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			redirectURL = string(bytes)
		}

		rows, err := postgres.Query(`SELECT user_id, email, name, password, salt FROM users WHERE email = $1 AND deleted_at IS NULL`, &claims.Email)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		defer rows.Close()

		var userID string
		var name string

		if rows.Next() {

			var user structs.UserEntity

			err = rows.Scan(&userID, &user.Email, &user.Name, &user.Password, &user.Salt)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			salt := uuid.New().String()

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte((*userGenericDTO.Password)+(salt)), HASH_COST)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			_, err = postgres.Exec(`
				UPDATE users SET updated_at = NOW(), password = $1, salt = $2 WHERE email = $3 AND deleted_at IS NULL
			`, string(hashedPassword), &salt, &claims.Email)

			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}
		} else {

			salt := uuid.New().String()

			(*userGenericDTO.Password) = (*userGenericDTO.Password) + (salt)

			hashedPassword, err := bcrypt.GenerateFromPassword([]byte((*userGenericDTO.Password)), HASH_COST)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			name = strings.Split(claims.Email, "@")[0]
			userID = uuid.New().String()

			_, err = postgres.Exec(`
				INSERT INTO users (created_at, user_id, name, email, password, salt) VALUES (NOW(), $1, $2, $3, $4, $5)
			`, &userID, &name, &claims.Email, string(hashedPassword), &salt)

			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			err = utils.CreateUserFolder(config, userID)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}
		}

		token, err := jwt.GetUserTokenString(userID, name, claims.Email, config.JWTKey)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)

		if len(claims.RedirectURL) > 0 {
			fmt.Fprintf(w, "{\"token\":\"%s\",\"redirect_url\":\"%s\"}", (*token), redirectURL)
		} else {
			fmt.Fprintf(w, "{\"token\":\"%s\"}", (*token))
		}
	}
}

func LoginUser(postgres *sql.DB, config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		var redirectURL = r.URL.Query().Get("redirect")
		if len(redirectURL) > 0 && (len(redirectURL)%2 == 0) {
			bytes, err := hex.DecodeString(redirectURL)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			redirectURL = string(bytes)
		}

		var body structs.UserLoginDTO

		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		if body.Email == nil || body.Password == nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrWrongPayload.Error())
			return
		}

		rows, err := postgres.Query(`SELECT user_id, name, email, password, salt FROM users WHERE email = $1 AND deleted_at IS NULL`, body.Email)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		defer rows.Close()

		if rows.Next() {

			var userID string
			var user structs.UserEntity

			err = rows.Scan(&userID, &user.Name, &user.Email, &user.Password, &user.Salt)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			if user.Password == nil || user.Salt == nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrPasswordNotSet.Error())
				return
			}

			err = bcrypt.CompareHashAndPassword(([]byte(*user.Password)), ([]byte((*body.Password) + (*user.Salt))))
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			token, err := jwt.GetUserTokenString(userID, (*user.Name), (*body.Email), config.JWTKey)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			w.WriteHeader(http.StatusOK)
			if len(redirectURL) > 0 {
				fmt.Fprintf(w, "{\"token\":\"%s\",\"redirect_url\":\"%s\"}", (*token), redirectURL)
			} else {
				fmt.Fprintf(w, "{\"token\":\"%s\"}", (*token))
			}
		} else {

			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrUserNotExists.Error())
		}
	}
}

func GetRedirectURLForOAuth(config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		to := r.URL.Query().Get("to")
		redirectURL := r.URL.Query().Get("redirect")

		switch to {
		case "google":
			url := oauth.GetGoogleLoginURL(config, redirectURL)

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "{\"redirect_url\":\"%s\"}", (*url))

			return
		case "github":
			url := oauth.GetGithubLoginURL(config, redirectURL)

			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "{\"redirect_url\":\"%s\"}", (*url))

			return
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
}

func HandleOAuthCallback(postgres *sql.DB, config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")

		states := strings.Split(state, "#")
		if len(states) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var userInfo map[string]string
		var err error

		switch states[0] {

		case "google":
			userInfo, err = oauth.GetGoogleUserInfo(config, code)

		case "github":
			userInfo, err = oauth.GetGithubUserInfo(config, code)

		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		var redirectURL string
		if len(states) > 1 {
			bytes, err := hex.DecodeString(states[1])
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			redirectURL = string(bytes)
		}

		rows, err := postgres.Query(`SELECT user_id, name, email FROM users WHERE email = $1 AND deleted_at IS NULL`, userInfo["email"])
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		defer rows.Close()

		if rows.Next() {

			var userID string
			var user structs.UserEntity

			err = rows.Scan(&userID, &user.Name, &user.Email)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			token, err := jwt.GetUserTokenString(userID, (*user.Name), (*user.Email), config.JWTKey)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			w.WriteHeader(http.StatusOK)

			if len(redirectURL) > 0 {
				fmt.Fprintf(w, "{\"token\":\"%s\",\"redirect_url\":\"%s\"}", (*token), redirectURL)
			} else {
				fmt.Fprintf(w, "{\"token\":\"%s\"}", (*token))
			}
		} else {

			email := userInfo["email"]
			name := userInfo["name"]

			userID := uuid.New().String()

			_, err = postgres.Exec(`
				INSERT INTO users (created_at, user_id, name, email) VALUES (NOW(), $1, $2, $3)
			`, &userID, &name, &email)

			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			err = utils.CreateUserFolder(config, userID)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			token, err := jwt.GetUserTokenString(userID, name, email, config.JWTKey)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			w.WriteHeader(http.StatusOK)

			if len(redirectURL) > 0 {
				fmt.Fprintf(w, "{\"token\":\"%s\",\"redirect_url\":\"%s\"}", (*token), redirectURL)
			} else {
				fmt.Fprintf(w, "{\"token\":\"%s\"}", (*token))
			}
		}
	}
}

func HandleRefresh(config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		tokenVerify := r.Header.Get("Authorization")

		if !strings.HasPrefix(tokenVerify, "Bearer ") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenVerify = strings.TrimPrefix(tokenVerify, "Bearer ")

		var redirectURL = r.URL.Query().Get("redirect")
		if len(redirectURL) > 0 && (len(redirectURL)%2 == 0) {
			bytes, err := hex.DecodeString(redirectURL)
			if err != nil {
				log.Default().Print(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
				return
			}

			redirectURL = string(bytes)
		}

		claims, err := jwt.VerifyUserTokenAndReturnClaims(tokenVerify, config.JWTKey)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", ErrNotAllowed.Error())
			return
		}

		token, err := jwt.GetUserTokenString(claims.UserID, claims.Name, claims.Email, config.JWTKey)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)

		if len(redirectURL) > 0 {
			fmt.Fprintf(w, "{\"token\":\"%s\",\"redirect_url\":\"%s\"}", (*token), redirectURL)
		} else {
			fmt.Fprintf(w, "{\"token\":\"%s\"}", (*token))
		}
	}
}

func InternalSignUp(postgres *sql.DB, config *structs.Config) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", CONTENT_TYPE)

		defer r.Body.Close()

		internalAuthCode := r.Header.Get("X-Internal-Auth")
		if internalAuthCode != config.InternalAuthCode {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var emails []string

		err := json.NewDecoder(r.Body).Decode(&emails)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		var mapper = make(map[string]string)

		for _, e := range emails {
			rows, err := postgres.Query(`SELECT user_id, email FROM users WHERE email = $1 AND deleted_at IS NULL`, &e)

			if err != nil {
				log.Default().Print(err.Error())
				continue
			}

			if rows.Next() {

				var userID string
				var email string

				err = rows.Scan(&userID, &email)
				if err != nil {
					log.Default().Print(err.Error())
					rows.Close()
					continue
				}

				mapper[email] = userID
			} else {

				var userID = uuid.New().String()

				var name = strings.Split(e, "@")[0]

				_, err = postgres.Exec(`
				INSERT INTO users (created_at, user_id, name, email) VALUES (NOW(), $1, $2, $3)
			`, &userID, &name, &e)

				if err != nil {
					log.Default().Print(err.Error())
					rows.Close()
					continue
				}

				mapper[e] = userID

				err = utils.CreateUserFolder(config, userID)
				if err != nil {
					log.Default().Print(err.Error())
					rows.Close()
					continue
				}
			}

			rows.Close()
		}

		responseBytes, err := json.Marshal(&mapper)
		if err != nil {
			log.Default().Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"%s\"}", err.Error())
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(responseBytes)
	}
}
