package conf

import (
	"errors"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

const DefaultGitHubEndpoint = "https://api.github.com"
const DefaultGitLabEndpoint = "https://gitlab.com/api/v4"
const DefaultGitLabTokenType = "oauth"
const DefaultBitBucketEndpoint = "https://api.bitbucket.org/2.0"

type GitHubConfig struct {
	AccessToken string `envconfig:"ACCESS_TOKEN" json:"access_token,omitempty"`
	Endpoint    string `envconfig:"ENDPOINT" json:"endpoint"`
	Repo        string `envconfig:"REPO" json:"repo"` // Should be "owner/repo" format
}

type GitLabConfig struct {
	AccessToken     string `envconfig:"ACCESS_TOKEN" json:"access_token,omitempty"`
	AccessTokenType string `envconfig:"ACCESS_TOKEN_TYPE" json:"access_token_type"`
	Endpoint        string `envconfig:"ENDPOINT" json:"endpoint"`
	Repo            string `envconfig:"REPO" json:"repo"` // Should be "owner/repo" format
}

type BitBucketConfig struct {
	RefreshToken string `envconfig:"REFRESH_TOKEN" json:"refresh_token,omitempty"`
	ClientID     string `envconfig:"CLIENT_ID" json:"client_id,omitempty"`
	ClientSecret string `envconfig:"CLIENT_SECRET" json:"client_secret,omitempty"`
	Endpoint     string `envconfig:"ENDPOINT" json:"endpoint"`
	Repo         string `envconfig:"REPO" json:"repo"`
}

// JWTConfiguration holds all the JWT related configuration.
type JWTConfiguration struct {
	SigningMethod string `json:"signing_method"`
	Secret        string `json:"secret" required:"false"`
	JWKs          string `json:"jwks" required:"false"`
	ClientID      string `json:"client_id" required:"true"`
}

// GlobalConfiguration holds all the configuration that applies to all instances.
type GlobalConfiguration struct {
	API struct {
		Host     string
		Port     int `envconfig:"PORT" default:"8081"`
		Endpoint string
	}
	Logging LoggingConfig `envconfig:"LOG"`
}

// Configuration holds all the per-instance configuration.
type Configuration struct {
	JWT       JWTConfiguration `json:"jwt"`
	GitHub    GitHubConfig     `envconfig:"GITHUB" json:"github"`
	GitLab    GitLabConfig     `envconfig:"GITLAB" json:"gitlab"`
	BitBucket BitBucketConfig  `envconfig:"BITBUCKET" json:"bitbucket"`
	Roles     []string         `envconfig:"ROLES" json:"roles"`
}

func loadEnvironment(filename string) error {
	var err error
	if filename != "" {
		err = godotenv.Load(filename)
	} else {
		err = godotenv.Load()
		// handle if .env file does not exist, this is OK
		if os.IsNotExist(err) {
			return nil
		}
	}
	return err
}

// LoadGlobal loads configuration from file and environment variables.
func LoadGlobal(filename string) (*GlobalConfiguration, error) {
	if err := loadEnvironment(filename); err != nil {
		return nil, err
	}

	config := new(GlobalConfiguration)
	if err := envconfig.Process("gitgateway", config); err != nil {
		return nil, err
	}
	if _, err := ConfigureLogging(&config.Logging); err != nil {
		return nil, err
	}
	return config, nil
}

// LoadConfig loads per-instance configuration.
func LoadConfig(filename string) (*Configuration, error) {
	if err := loadEnvironment(filename); err != nil {
		return nil, err
	}

	config := new(Configuration)
	if err := envconfig.Process("gitgateway", config); err != nil {
		return nil, err
	}
	config.ApplyDefaults()
	if strings.HasPrefix(config.JWT.SigningMethod, "HS") && config.JWT.Secret == "" {
		return nil, errors.New("required key GITGATEWAY_JWT_SECRET needs to be set for HMAC based signing")
	}

	if strings.HasPrefix(config.JWT.SigningMethod, "RS") && config.JWT.JWKs == "" {
		return nil, errors.New("required key GITGATEWAY_JWT_JWKS needs to be set for RSA signing")
	}
	return config, nil
}

// ApplyDefaults sets defaults for a Configuration
func (config *Configuration) ApplyDefaults() {
	if config.GitHub.Endpoint == "" {
		config.GitHub.Endpoint = DefaultGitHubEndpoint
	}
	if config.GitLab.Endpoint == "" {
		config.GitLab.Endpoint = DefaultGitLabEndpoint
	}
	if config.GitLab.AccessTokenType == "" {
		config.GitLab.AccessTokenType = DefaultGitLabTokenType
	}
	if config.BitBucket.Endpoint == "" {
		config.BitBucket.Endpoint = DefaultBitBucketEndpoint
	}
	if config.JWT.SigningMethod == "" {
		config.JWT.SigningMethod = "HS256"
	}
}
