package oauth

import (
	"context"
	"errors"
	"login/structs"

	"github.com/google/go-github/v44/github"
	"golang.org/x/oauth2"
)

func NewGithubOAuthConfig(config *structs.Config) *oauth2.Config {

	oauth_config := oauth2.Config{
		ClientID:     config.OAuth["github"].ClientID,
		ClientSecret: config.OAuth["github"].ClientSecret,
		RedirectURL:  config.OAuth["github"].RedirectURL,
		Scopes:       config.OAuth["github"].Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},

	}

	return &oauth_config
}

func GetGithubLoginURL(config *structs.Config, extra string) *string {

	oauth_config := NewGithubOAuthConfig(config)
	url := oauth_config.AuthCodeURL((config.OAuth["google"].State + "#" + extra), oauth2.AccessTypeOffline)

	return &url
}

func GetGithubUserInfo(config *structs.Config, code string) (map[string]string, error) {

	authConfig := NewGithubOAuthConfig(config)

	token, err := authConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	user, _, err := github.NewClient(authConfig.Client(context.Background(), token)).Users.Get(context.Background(), "")
	if err != nil {
		return nil, err
	}

	if user.Name == nil || user.Email == nil {
		return nil, errors.New("either name or email is nil")
	}

	return map[string]string{"name": (*user.Name), "email": (*user.Email)}, nil
}
