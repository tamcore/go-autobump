package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tamcore/go-autobump/internal/config"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "go-autobump",
	Short: "Automatically update vulnerable Go dependencies",
	Long: `go-autobump uses Trivy to scan Go modules for vulnerabilities and
automatically updates dependencies to their fixed versions based on
configurable CVSS score thresholds.

It handles direct and indirect dependencies differently:
- Direct dependencies are updated to their nearest fixed version
- Indirect dependencies are traced back to their direct dependency
  and updated through the dependency chain`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./.autobump.yaml)")
	rootCmd.PersistentFlags().String("path", ".", "target directory to scan")
	rootCmd.PersistentFlags().Float64("cvss-threshold", 7.0, "minimum CVSS score to act on")
	rootCmd.PersistentFlags().Bool("dry-run", false, "preview changes without applying them")
	rootCmd.PersistentFlags().Bool("skip-tidy", false, "skip running 'go mod tidy' after updates")
	rootCmd.PersistentFlags().Bool("allow-major", false, "allow major version bumps")

	// VEX generation flags
	rootCmd.PersistentFlags().Bool("generate-vex", false, "generate VEX documents for unfixed CVEs")
	rootCmd.PersistentFlags().String("vex-output", ".vex.openvex.json", "output path for VEX documents")

	// AI configuration flags
	rootCmd.PersistentFlags().String("ai-api-key", "", "API key for AI provider (or use AUTOBUMP_AI_API_KEY)")
	rootCmd.PersistentFlags().String("ai-endpoint", "https://api.openai.com/v1", "AI API endpoint")
	rootCmd.PersistentFlags().String("ai-model", "gpt-4o", "AI model to use")

	// Bind flags to Viper
	viper.BindPFlag("path", rootCmd.PersistentFlags().Lookup("path"))
	viper.BindPFlag("cvss-threshold", rootCmd.PersistentFlags().Lookup("cvss-threshold"))
	viper.BindPFlag("dry-run", rootCmd.PersistentFlags().Lookup("dry-run"))
	viper.BindPFlag("skip-tidy", rootCmd.PersistentFlags().Lookup("skip-tidy"))
	viper.BindPFlag("allow-major", rootCmd.PersistentFlags().Lookup("allow-major"))
	viper.BindPFlag("generate-vex", rootCmd.PersistentFlags().Lookup("generate-vex"))
	viper.BindPFlag("vex-output", rootCmd.PersistentFlags().Lookup("vex-output"))
	viper.BindPFlag("ai.api-key", rootCmd.PersistentFlags().Lookup("ai-api-key"))
	viper.BindPFlag("ai.endpoint", rootCmd.PersistentFlags().Lookup("ai-endpoint"))
	viper.BindPFlag("ai.model", rootCmd.PersistentFlags().Lookup("ai-model"))
}

func initConfig() {
	config.SetupViper()

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
