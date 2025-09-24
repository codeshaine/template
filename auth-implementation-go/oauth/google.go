package oauth

import (
	"context"
	"encoding/json"
	"io"
	"login/structs"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func NewGoogleOAuthConfig(config *structs.Config) *oauth2.Config {

	oauth_config := oauth2.Config{
		ClientID:     config.OAuth["google"].ClientID,
		ClientSecret: config.OAuth["google"].ClientSecret,
		RedirectURL:  config.OAuth["google"].RedirectURL,
		Scopes:       config.OAuth["google"].Scopes,
		Endpoint:     google.Endpoint,
	}

	return &oauth_config
}

func GetGoogleLoginURL(config *structs.Config, extra string) *string {

	oauth_config := NewGoogleOAuthConfig(config)
	url := oauth_config.AuthCodeURL((config.OAuth["google"].State + "#" + extra), oauth2.AccessTypeOffline)

	return &url
}

func GetGoogleUserInfo(config *structs.Config, code string) (map[string]string, error) {

	authConfig := NewGoogleOAuthConfig(config)

	token, err := authConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var data map[string]any = make(map[string]any)

	err = json.Unmarshal(contents, &data)
	if err != nil {
		return nil, err
	}

	return map[string]string{"name": data["name"].(string), "email": data["email"].(string)}, nil
}
