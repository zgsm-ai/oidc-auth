package config

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type AppConfig struct {
	Server       Server                    `json:"Server" mapstructure:"Server" validate:"required"`
	Log          LogConfig                 `json:"log" mapstructure:"log" validate:"required"`
	Database     DatabaseConfig            `json:"database" mapstructure:"database" validate:"required"`
	GithubConfig GithubStarConfig          `json:"sync_star" mapstructure:"sync_star" validate:"required"`
	Encrypt      EncryptConfig             `json:"encrypt" mapstructure:"encrypt" validate:"required"`
	Providers    map[string]ProviderConfig `json:"providers" mapstructure:"providers"`
}

type Server struct {
	ServerPort string `json:"serverPort" mapstructure:"serverPort" validate:"required,numeric"`
	BaseURL    string `json:"baseURL" mapstructure:"baseURL"`
}

type LogConfig struct {
	Level      string `json:"level" mapstructure:"level" validate:"required,oneof=debug info warn error fatal"`
	Filename   string `json:"filename" mapstructure:"filename"`
	MaxSize    int    `json:"maxSize" mapstructure:"maxSize"`
	MaxBackups int    `json:"maxBackups" mapstructure:"maxBackups"`
	MaxAge     int    `json:"maxAge" mapstructure:"maxAge"`
	Compress   bool   `json:"compress" mapstructure:"compress"`
}

type DatabaseConfig struct {
	Type         string `json:"type" mapstructure:"type" validate:"required,oneof=mysql postgres"`
	Host         string `json:"host" mapstructure:"host" validate:"required"`
	Port         int    `json:"port" mapstructure:"port" validate:"required,min=1,max=65535"`
	Username     string `json:"username" mapstructure:"username" validate:"required"`
	Password     string `json:"password" mapstructure:"password" validate:"required"`
	DBName       string `json:"dbname" mapstructure:"dbname" validate:"required"`
	MaxIdleConns int    `json:"maxIdleConns" mapstructure:"maxIdleConns" validate:"omitempty,min=1"`
	MaxOpenConns int    `json:"maxOpenConns" mapstructure:"maxOpenConns" validate:"omitempty,min=1"`
}

type GithubStarConfig struct {
	Enabled       bool
	PersonalToken string        `json:"personalToken" mapstructure:"personalToken" validate:"required"`
	Owner         string        `json:"owner" mapstructure:"owner" validate:"required"`
	Repo          string        `json:"repo" mapstructure:"repo" validate:"required"`
	Interval      time.Duration `json:"interval" mapstructure:"interval" validate:"required"`
}

type EncryptConfig struct {
	PrivateKeyPath string `json:"private_key_path" mapstructure:"private_key_path" validate:"required"`
	PublicKeyPath  string `json:"public_key_path" mapstructure:"public_key_path" validate:"required"`
	AesKey         string `json:"aes_key" mapstructure:"aes_key" validate:"required"`
	EnableRsa      string `json:"enable_rsa" mapstructure:"enable_rsa"`
}

type ProviderConfig struct {
	ClientID     string `json:"clientID" mapstructure:"clientID"`
	ClientSecret string `json:"clientSecret" mapstructure:"clientSecret"`
	RedirectURL  string `json:"redirectURL" mapstructure:"redirectURL"`
	EncryptKey   string `json:"encryptKey" mapstructure:"encryptKey"`
	Endpoint     string `json:"endpoint" mapstructure:"endpoint"`
}

const (
	EnvPrefix         = ""
	DefaultConfigDir  = "."
	DefaultConfigName = "config"
	DefaultConfigType = "yaml"
)

func InitConfig(cfgFile string) (*AppConfig, error) {
	cfg := new(AppConfig)
	viper.SetDefault("serverPort", "8080")
	viper.SetDefault("log.level", "info")

	viper.SetDefault("database.maxIdleConns", 10)
	viper.SetDefault("database.maxOpenConns", 100)

	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // eg: DATABASE_HOST for database.host

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(DefaultConfigDir)
		viper.SetConfigName(DefaultConfigName)
		viper.SetConfigType(DefaultConfigType)
	}

	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			log.Println("Config file not found, using defaults and environment variables.")
		}
	} else {
		log.Printf("Configuration loaded from: %s", viper.ConfigFileUsed())
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	log.Println("Configuration initialized and validated successfully.")
	return cfg, nil
}
