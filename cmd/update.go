package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tamcore/go-autobump/internal/config"
	"github.com/tamcore/go-autobump/internal/scanner"
	"github.com/tamcore/go-autobump/internal/trivy"
	"github.com/tamcore/go-autobump/internal/updater"
	"github.com/tamcore/go-autobump/internal/vex"
)

var updateCmd = &cobra.Command{
	Use:   "update [path]",
	Short: "Update vulnerable dependencies",
	Long: `Update scans for vulnerabilities and automatically updates dependencies
to their fixed versions.

Direct dependencies are updated to their nearest fixed version.
Indirect dependencies are traced back through the dependency chain
and updated by modifying the appropriate direct dependency.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	cfg, err := config.Get()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override path if provided as argument
	if len(args) > 0 {
		cfg.Path = args[0]
	}

	// Discover all go.mod files
	goModFiles, err := scanner.DiscoverGoModFiles(cfg.Path)
	if err != nil {
		return fmt.Errorf("failed to discover go.mod files: %w", err)
	}

	if len(goModFiles) == 0 {
		fmt.Println("No go.mod files found")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Found %d go.mod file(s)\n", len(goModFiles))

	var unfixedVulns []trivy.Vulnerability

	for _, goModFile := range goModFiles {
		fmt.Fprintf(os.Stderr, "\n📁 Processing %s\n", goModFile)

		// Initial scan
		result, err := trivy.Scan(goModFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to scan %s: %v\n", goModFile, err)
			continue
		}

		// Filter by CVSS threshold
		filtered := trivy.FilterByCVSS(result, cfg.CVSSThreshold)
		if len(filtered.Vulnerabilities) == 0 {
			fmt.Fprintf(os.Stderr, "  ✅ No vulnerabilities above CVSS %.1f\n", cfg.CVSSThreshold)
			continue
		}

		fmt.Fprintf(os.Stderr, "  Found %d vulnerabilities above CVSS %.1f\n",
			len(filtered.Vulnerabilities), cfg.CVSSThreshold)

		// Process each vulnerability
		for _, vuln := range filtered.Vulnerabilities {
			if vuln.FixedVersion == "" {
				fmt.Fprintf(os.Stderr, "  ⚠️  %s in %s: no fix available\n",
					vuln.VulnerabilityID, vuln.PkgName)
				unfixedVulns = append(unfixedVulns, vuln)
				continue
			}

			if cfg.DryRun {
				fmt.Fprintf(os.Stderr, "  🔍 [dry-run] Would update %s: %s -> %s\n",
					vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion)
				continue
			}

			var updateErr error
			if vuln.Indirect {
				updateErr = updater.UpdateIndirect(goModFile, vuln, cfg)
			} else {
				updateErr = updater.UpdateDirect(goModFile, vuln, cfg)
			}

			if updateErr != nil {
				fmt.Fprintf(os.Stderr, "  ❌ Failed to update %s: %v\n",
					vuln.PkgName, updateErr)
				continue
			}

			fmt.Fprintf(os.Stderr, "  ✅ Updated %s: %s -> %s\n",
				vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion)
		}

		// Verify updates
		if !cfg.DryRun {
			if err := updater.Verify(goModFile, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  Verification warning: %v\n", err)
			}
		}
	}

	// Generate VEX for unfixed vulnerabilities
	if cfg.GenerateVEX && len(unfixedVulns) > 0 {
		fmt.Fprintf(os.Stderr, "\n📝 Generating VEX document for %d unfixed vulnerabilities...\n",
			len(unfixedVulns))

		if err := vex.Generate(unfixedVulns, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to generate VEX: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "  ✅ VEX document written to %s\n", cfg.VEXOutput)
		}
	}

	return nil
}
