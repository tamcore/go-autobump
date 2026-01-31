package updater

import (
	"fmt"

	"github.com/tamcore/go-autobump/internal/config"
	"github.com/tamcore/go-autobump/internal/gomod"
	"github.com/tamcore/go-autobump/internal/trivy"
)

// Verify rescans the module after updates and reports remaining vulnerabilities
func Verify(goModPath string, cfg *config.Config) error {
	// Rescan with Trivy
	result, err := trivy.Scan(goModPath)
	if err != nil {
		return fmt.Errorf("verification scan failed: %w", err)
	}

	// Filter by CVSS threshold
	filtered := trivy.FilterByCVSS(result, cfg.CVSSThreshold)

	if len(filtered.Vulnerabilities) == 0 {
		fmt.Printf("  ✅ Verification passed: no vulnerabilities above CVSS %.1f\n", cfg.CVSSThreshold)
		return nil
	}

	// Report remaining vulnerabilities
	fmt.Printf("  ⚠️  %d vulnerabilities still present after updates:\n", len(filtered.Vulnerabilities))
	for _, vuln := range filtered.Vulnerabilities {
		status := "fixable"
		if vuln.FixedVersion == "" {
			status = "no fix available"
		}
		fmt.Printf("      - %s in %s@%s (CVSS: %.1f, %s)\n",
			vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion, vuln.CVSSScore, status)
	}

	return nil
}

// VerifyVulnerabilityFixed checks if a specific vulnerability has been fixed
func VerifyVulnerabilityFixed(goModPath string, vulnID, pkgName string, threshold float64) (bool, error) {
	result, err := trivy.Scan(goModPath)
	if err != nil {
		return false, fmt.Errorf("verification scan failed: %w", err)
	}

	filtered := trivy.FilterByCVSS(result, threshold)

	for _, vuln := range filtered.Vulnerabilities {
		if vuln.VulnerabilityID == vulnID && vuln.PkgName == pkgName {
			return false, nil // Still present
		}
	}

	return true, nil // Fixed
}

// RunGoModTidy runs go mod tidy in the module directory
func RunGoModTidy(goModPath string) error {
	moduleDir := gomod.GetModuleDir(goModPath)
	return gomod.ModTidy(moduleDir)
}
