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
	rootCmd.PersistentFlags().StringSlice("exclude", []string{}, "glob patterns to exclude (e.g., 'examples/*/go.mod')")
	rootCmd.PersistentFlags().Float64("cvss-threshold", 7.0, "minimum CVSS score to act on")
	rootCmd.PersistentFlags().Bool("dry-run", false, "preview changes without applying them")
	rootCmd.PersistentFlags().Bool("skip-tidy", false, "skip running 'go mod tidy' after updates")
	rootCmd.PersistentFlags().Bool("allow-major", false, "allow major version bumps")

	// Trivy configuration
	rootCmd.PersistentFlags().Bool("skip-trivy-db-update", false, "skip downloading Trivy DB (use only if DB is pre-downloaded)")

	// VEX generation flags
	rootCmd.PersistentFlags().Bool("generate-vex", false, "generate VEX documents for unfixed CVEs")
	rootCmd.PersistentFlags().String("vex-output", ".vex.openvex.json", "output path for VEX documents")

	// AI configuration flags
	rootCmd.PersistentFlags().String("ai-api-key", "", "API key for AI provider (or use AUTOBUMP_AI_API_KEY)")
	rootCmd.PersistentFlags().String("ai-endpoint", "https://api.openai.com/v1", "AI API endpoint")
	rootCmd.PersistentFlags().String("ai-model", "gpt-4o", "AI model to use")

	// Bind flags to Viper (errors are ignored as these are non-critical)
	_ = viper.BindPFlag("path", rootCmd.PersistentFlags().Lookup("path"))
	_ = viper.BindPFlag("exclude", rootCmd.PersistentFlags().Lookup("exclude"))
	_ = viper.BindPFlag("cvss-threshold", rootCmd.PersistentFlags().Lookup("cvss-threshold"))
	_ = viper.BindPFlag("dry-run", rootCmd.PersistentFlags().Lookup("dry-run"))
	_ = viper.BindPFlag("skip-tidy", rootCmd.PersistentFlags().Lookup("skip-tidy"))
	_ = viper.BindPFlag("allow-major", rootCmd.PersistentFlags().Lookup("allow-major"))
	_ = viper.BindPFlag("skip-trivy-db-update", rootCmd.PersistentFlags().Lookup("skip-trivy-db-update"))
	_ = viper.BindPFlag("generate-vex", rootCmd.PersistentFlags().Lookup("generate-vex"))
	_ = viper.BindPFlag("vex-output", rootCmd.PersistentFlags().Lookup("vex-output"))
	_ = viper.BindPFlag("ai.api-key", rootCmd.PersistentFlags().Lookup("ai-api-key"))
	_ = viper.BindPFlag("ai.endpoint", rootCmd.PersistentFlags().Lookup("ai-endpoint"))
	_ = viper.BindPFlag("ai.model", rootCmd.PersistentFlags().Lookup("ai-model"))
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
