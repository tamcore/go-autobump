package updater

import (
	"fmt"

	"github.com/tamcore/go-autobump/internal/config"
	"github.com/tamcore/go-autobump/internal/gomod"
	"github.com/tamcore/go-autobump/internal/trivy"
)

// UpdateDirect updates a direct dependency to its fixed version
func UpdateDirect(goModPath string, vuln trivy.Vulnerability, cfg *config.Config) error {
	moduleDir := gomod.GetModuleDir(goModPath)

	// Check for major version bump
	if gomod.IsMajorVersionBump(vuln.InstalledVersion, vuln.FixedVersion) {
		if !cfg.AllowMajor {
			return fmt.Errorf("major version bump required (%s -> %s), use --allow-major to permit",
				vuln.InstalledVersion, vuln.FixedVersion)
		}
		fmt.Printf("  ⚠️  Major version bump: %s -> %s\n", vuln.InstalledVersion, vuln.FixedVersion)
	}

	// Run go get to update the dependency
	if err := gomod.GoGet(moduleDir, vuln.PkgName, vuln.FixedVersion); err != nil {
		return fmt.Errorf("failed to update %s: %w", vuln.PkgName, err)
	}

	// Run go mod tidy unless skipped
	if !cfg.SkipTidy {
		if err := gomod.ModTidy(moduleDir); err != nil {
			return fmt.Errorf("go mod tidy failed: %w", err)
		}
	}

	return nil
}
