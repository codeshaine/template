package jwt

import (
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CustomUserClaims struct {
	UserID string `json:"user_id,omitempty"`
	Name   string `json:"name,omitempty"`
	Email  string `json:"email_id,omitempty"`
	jwt.RegisteredClaims
}

type CustomEmailClaims struct {
	Email       string `json:"email_id,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	jwt.RegisteredClaims
}

func GetUserTokenString(userID string, name string, email string, secretKey string) (*string, error) {

	var customClaims CustomUserClaims
	customClaims.UserID = userID
	customClaims.Email = email
	customClaims.Name = name
	customClaims.ExpiresAt = &jwt.NumericDate{Time: time.Now().Add(time.Hour * 24 * 7)}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &customClaims)

	tokenString, err := jwtToken.SignedString([]byte(secretKey))
	if err != nil {
		log.Default().Print(err.Error())
		return nil, err
	}

	return &tokenString, nil
}

func GetEmailTokenString(email string, redirectURL string, secretKey string) (*string, error) {

	var customClaims CustomEmailClaims
	customClaims.Email = email
	customClaims.RedirectURL = redirectURL
	customClaims.ExpiresAt = &jwt.NumericDate{Time: time.Now().Add(time.Hour * 24)}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &customClaims)

	tokenString, err := jwtToken.SignedString([]byte(secretKey))
	if err != nil {
		log.Default().Print(err.Error())
		return nil, err
	}

	return &tokenString, nil
}

func VerifyUserTokenAndReturnClaims(tokenString string, secretKey string) (*CustomUserClaims, error) {

	jwtToken, err := jwt.ParseWithClaims((tokenString), &CustomUserClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Default().Print(err.Error())
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, errors.New("token is not valid")
	}

	return jwtToken.Claims.(*CustomUserClaims), nil
}

func VerifyEmailTokenAndReturnClaims(tokenString string, secretKey string) (*CustomEmailClaims, error) {

	jwtToken, err := jwt.ParseWithClaims((tokenString), &CustomEmailClaims{}, func(t *jwt.Token) (any, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, errors.New("token is not valid")
	}

	return jwtToken.Claims.(*CustomEmailClaims), nil
}
