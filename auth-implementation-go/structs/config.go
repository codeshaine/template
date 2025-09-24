package structs

type OAuthConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  string   `json:"redirect_url"`
	State        string   `json:"state"`
	Scopes       []string `json:"scopes"`
}

type CorsConfig struct {
	Origins          []string `json:"origins"`
	Headers          []string `json:"headers"`
	Methods          []string `json:"methods"`
	AllowCredentials bool     `json:"allow_credentials"`
}

type Config struct {
	EmailSubSystemURL string                 `json:"email_subsystem_url"`
	PostgresURL       string                 `json:"postgres_url"`
	JWTKey            string                 `json:"jwt_key"`
	Sender            string                 `json:"sender"`
	ReplyTo           string                 `json:"reply_to"`
	RedirectURL       string                 `json:"redirect_url"`
	WorkDir           string                 `json:"workdir"`
	EmailAuthToken    string                 `json:"email_auth_token"`
	InternalAuthCode  string                 `json:"internal_auth_code"`
	Limit             int                    `json:"limit"`
	ServerPort        int                    `json:"server_port"`
	HashCost          int                    `json:"hash_cost"`
	OAuth             map[string]OAuthConfig `json:"oauth"`
	Cors              CorsConfig             `json:"cors"`
}
