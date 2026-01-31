package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tamcore/go-autobump/internal/config"
	"github.com/tamcore/go-autobump/internal/scanner"
	"github.com/tamcore/go-autobump/internal/trivy"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan for vulnerable dependencies",
	Long: `Scan recursively searches for go.mod files and uses Trivy to identify
vulnerabilities above the configured CVSS threshold.

Results are displayed in a table format by default, or as JSON with --json flag.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var (
	scanOutputJSON bool
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().BoolVar(&scanOutputJSON, "json", false, "output results as JSON")
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := config.Get()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override path if provided as argument
	if len(args) > 0 {
		cfg.Path = args[0]
	}

	// Discover all go.mod files
	goModFiles, err := scanner.DiscoverGoModFiles(cfg.Path, cfg.Exclude...)
	if err != nil {
		return fmt.Errorf("failed to discover go.mod files: %w", err)
	}

	if len(goModFiles) == 0 {
		fmt.Println("No go.mod files found")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d go.mod file(s)\n", len(goModFiles))

	var allResults []trivy.ScanResult

	for _, goModFile := range goModFiles {
		fmt.Fprintf(os.Stderr, "Scanning %s...\n", goModFile)

		result, err := trivy.Scan(goModFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to scan %s: %v\n", goModFile, err)
			continue
		}

		// Filter by CVSS threshold
		filtered := trivy.FilterByCVSS(result, cfg.CVSSThreshold)
		if len(filtered.Vulnerabilities) > 0 {
			allResults = append(allResults, filtered)
		}
	}

	if len(allResults) == 0 {
		fmt.Println("No vulnerabilities found above CVSS threshold", cfg.CVSSThreshold)
		return nil
	}

	if scanOutputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(allResults)
	}

	// Print table format
	printScanResults(allResults, cfg.CVSSThreshold)
	return nil
}

func printScanResults(results []trivy.ScanResult, threshold float64) {
	fmt.Printf("\nVulnerabilities found (CVSS >= %.1f):\n", threshold)
	fmt.Println(strings.Repeat("=", 100))

	totalVulns := 0
	for _, result := range results {
		fmt.Printf("\n📁 %s\n", result.Target)
		fmt.Println(strings.Repeat("-", 100))
		fmt.Printf("%-20s %-40s %-12s %-12s %-8s %s\n",
			"CVE", "Package", "Installed", "Fixed", "CVSS", "Direct")
		fmt.Println(strings.Repeat("-", 100))

		for _, vuln := range result.Vulnerabilities {
			direct := "yes"
			if vuln.Indirect {
				direct = "no"
			}
			fixed := vuln.FixedVersion
			if fixed == "" {
				fixed = "(none)"
			}
			fmt.Printf("%-20s %-40s %-12s %-12s %-8.1f %s\n",
				truncate(vuln.VulnerabilityID, 20),
				truncate(vuln.PkgName, 40),
				truncate(vuln.InstalledVersion, 12),
				truncate(fixed, 12),
				vuln.CVSSScore,
				direct,
			)
			totalVulns++
		}
	}

	fmt.Println(strings.Repeat("=", 100))
	fmt.Printf("Total: %d vulnerabilities in %d module(s)\n", totalVulns, len(results))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
