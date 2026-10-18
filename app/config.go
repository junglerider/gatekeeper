package app

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	MasterKey string `yaml:"masterKey"`
	Server    struct {
		Port           int    `yaml:"port"`
		LogLevel       string `yaml:"logLevel"`
		LogRequests    bool   `yaml:"logRequests"`
		PrettyPrint    bool   `yaml:"prettyPrint"`
		ApiKeyCacheTTL int    `yaml:"apiKeyCacheTTL"`
	} `yaml:"server"`
	DB struct {
		Driver   string `yaml:"driver"`
		Host     string `yaml:"host"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Port     int    `yaml:"port"`
		Database string `yaml:"database"`
		Timezone string `yaml:"timezone"`
		TLS      struct {
			Enabled    bool   `yaml:"enabled"`
			SkipVerify bool   `yaml:"skipVerify"`
			CACert     string `yaml:"caCert"`
		} `yaml:"tls"`
	} `yaml:"db"`
	Realms map[string]RealmConfig `yaml:"realms"`
}

type RealmConfig struct {
	SigningPrivateKey     string         `yaml:"signingPrivateKey"`
	VerificationPublicKey string         `yaml:"verificationPublicKey"`
	MinPasswordLength     int            `yaml:"minPasswordLength"`
	AccessTokenLifetime   int            `yaml:"accessTokenLifetime"`
	RefreshTokenLifetime  int            `yaml:"refreshTokenLifetime"`
	SessionMaxLifetime    int            `yaml:"sessionMaxLifetime"`
	Claims                map[string]any `yaml:"claims"`
}

// reads configuration from specific YAML file and environment vars
func ReadConfig() (*Config, error) {
	var config *Config

	yamlFile, err := os.ReadFile("./config.yml")
	if err != nil {
		return nil, err
	}

	_ = godotenv.Load() // load variables from .env file if it exists
	configData := os.ExpandEnv(string(yamlFile))

	err = yaml.Unmarshal([]byte(configData), &config)
	if err != nil {
		return nil, err
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func (config *Config) validate() error {
	var validationErrors []error
	if strings.TrimSpace(config.MasterKey) == "" {
		validationErrors = append(validationErrors, errors.New("masterKey is required"))
	} else if key, err := base64.StdEncoding.DecodeString(config.MasterKey); err != nil || len(key) != 32 {
		validationErrors = append(validationErrors, errors.New("masterKey must be base64-encoded 32-byte key material"))
	}
	if strings.TrimSpace(config.DB.User) == "" {
		validationErrors = append(validationErrors, errors.New("db.user is required"))
	}
	if config.DB.Driver != "" && config.DB.Driver != "mysql" && config.DB.Driver != "postgres" {
		validationErrors = append(validationErrors, errors.New("db.driver must be either mysql or postgres"))
	}
	if strings.TrimSpace(config.DB.Password) == "" {
		validationErrors = append(validationErrors, errors.New("db.password is required"))
	}
	if strings.TrimSpace(config.DB.Database) == "" {
		validationErrors = append(validationErrors, errors.New("db.database is required"))
	}
	if strings.TrimSpace(config.DB.TLS.CACert) != "" && !config.DB.TLS.Enabled {
		validationErrors = append(validationErrors, errors.New("db.tls.caCert requires db.tls.enabled"))
	}
	if config.DB.TLS.SkipVerify && !config.DB.TLS.Enabled {
		validationErrors = append(validationErrors, errors.New("db.tls.skipVerify requires db.tls.enabled"))
	}
	if config.Server.ApiKeyCacheTTL <= 0 {
		validationErrors = append(validationErrors, errors.New("server.apiKeyCacheTTL must be a positive integer"))
	}
	for name, realm := range config.Realms {
		if strings.Contains(name, ":") {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.name must not contain ':'", name))
		}
		var privateSeed []byte
		if strings.TrimSpace(realm.SigningPrivateKey) == "" {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.signingPrivateKey is required", name))
		} else if decoded, err := base64.StdEncoding.DecodeString(realm.SigningPrivateKey); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.signingPrivateKey must be base64-encoded: %w", name, err))
		} else if len(decoded) != ed25519.SeedSize {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.signingPrivateKey must encode a %d-byte Ed25519 seed", name, ed25519.SeedSize))
		} else {
			privateSeed = decoded
		}
		var publicKey []byte
		if strings.TrimSpace(realm.VerificationPublicKey) == "" {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.verificationPublicKey is required", name))
		} else if decoded, err := base64.StdEncoding.DecodeString(realm.VerificationPublicKey); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.verificationPublicKey must be base64-encoded: %w", name, err))
		} else if len(decoded) != ed25519.PublicKeySize {
			validationErrors = append(validationErrors, fmt.Errorf("realms.%s.verificationPublicKey must encode a %d-byte Ed25519 public key", name, ed25519.PublicKeySize))
		} else {
			publicKey = decoded
		}
		if len(privateSeed) == ed25519.SeedSize && len(publicKey) == ed25519.PublicKeySize {
			expectedPublicKey := ed25519.NewKeyFromSeed(privateSeed).Public().(ed25519.PublicKey)
			if subtle.ConstantTimeCompare(publicKey, expectedPublicKey) != 1 {
				validationErrors = append(validationErrors, fmt.Errorf("realms.%s.verificationPublicKey does not match signingPrivateKey", name))
			}
		}
	}
	return errors.Join(validationErrors...)
}
