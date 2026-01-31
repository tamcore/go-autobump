package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Config holds all configuration options for go-autobump
type Config struct {
	// Path is the target directory to scan (default: ".")
	Path string `mapstructure:"path"`

	// Exclude is a list of glob patterns to exclude from scanning
	Exclude []string `mapstructure:"exclude"`

	// CVSSThreshold is the minimum CVSS score to act on (e.g., 7.0)
	CVSSThreshold float64 `mapstructure:"cvss-threshold"`

	// SkipTidy disables running "go mod tidy" after updates
	SkipTidy bool `mapstructure:"skip-tidy"`

	// DryRun previews changes without applying them
	DryRun bool `mapstructure:"dry-run"`

	// AllowMajor permits major version bumps (e.g., v1 -> v2)
	AllowMajor bool `mapstructure:"allow-major"`

	// GenerateVEX enables VEX document generation for unfixed CVEs
	GenerateVEX bool `mapstructure:"generate-vex"`

	// VEXOutput is the output path for VEX documents
	VEXOutput string `mapstructure:"vex-output"`

	// AI configuration for VEX generation
	AI AIConfig `mapstructure:"ai"`
}

// AIConfig holds configuration for the AI provider used for VEX generation
type AIConfig struct {
	// APIKey is the API key for the AI provider
	APIKey string `mapstructure:"api-key"`

	// Endpoint is the API endpoint (OpenAI-compatible)
	Endpoint string `mapstructure:"endpoint"`

	// Model is the model identifier to use
	Model string `mapstructure:"model"`
}

// Default returns a Config with default values
func Default() *Config {
	return &Config{
		Path:          ".",
		Exclude:       []string{},
		CVSSThreshold: 7.0,
		SkipTidy:      false,
		DryRun:        false,
		AllowMajor:    false,
		GenerateVEX:   false,
		VEXOutput:     ".vex.openvex.json",
		AI: AIConfig{
			Endpoint: "https://api.openai.com/v1",
			Model:    "gpt-4o",
		},
	}
}

// SetupViper configures Viper to read from config file, env vars, and set defaults
func SetupViper() {
	// Set default values
	defaults := Default()
	viper.SetDefault("path", defaults.Path)
	viper.SetDefault("exclude", defaults.Exclude)
	viper.SetDefault("cvss-threshold", defaults.CVSSThreshold)
	viper.SetDefault("skip-tidy", defaults.SkipTidy)
	viper.SetDefault("dry-run", defaults.DryRun)
	viper.SetDefault("allow-major", defaults.AllowMajor)
	viper.SetDefault("generate-vex", defaults.GenerateVEX)
	viper.SetDefault("vex-output", defaults.VEXOutput)
	viper.SetDefault("ai.endpoint", defaults.AI.Endpoint)
	viper.SetDefault("ai.model", defaults.AI.Model)

	// Config file settings
	viper.SetConfigName(".autobump")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME")

	// Environment variable settings
	viper.SetEnvPrefix("AUTOBUMP")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()
}

// Load reads the configuration from all sources and returns a Config struct
func Load() (*Config, error) {
	SetupViper()

	// Try to read config file (ignore if not found)
	_ = viper.ReadInConfig()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Get returns a Config populated from Viper's current state
func Get() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
