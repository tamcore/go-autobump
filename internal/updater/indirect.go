package updater

import (
	"fmt"
	"strings"

	"github.com/tamcore/go-autobump/internal/config"
	"github.com/tamcore/go-autobump/internal/gomod"
	"github.com/tamcore/go-autobump/internal/trivy"
)

// UpdateIndirect updates an indirect dependency through the dependency chain
// Strategy:
// 1. First try direct update of the indirect dep
// 2. Run go mod tidy
// 3. Rescan to check if CVE persists
// 4. If CVE persists, find which direct dep imports it and update that
func UpdateIndirect(goModPath string, vuln trivy.Vulnerability, cfg *config.Config) error {
	moduleDir := gomod.GetModuleDir(goModPath)

	// Step 1: Try direct update of the indirect dependency
	fmt.Printf("  🔄 Attempting to update indirect dependency %s@%s -> %s\n",
		vuln.PkgName, vuln.InstalledVersion, vuln.FixedVersion)

	if err := gomod.GoGet(moduleDir, vuln.PkgName, vuln.FixedVersion); err != nil {
		// Direct update of indirect failed, need to go through direct deps
		fmt.Printf("  ℹ️  Direct update failed, tracing dependency chain...\n")
		return updateThroughDirectDep(goModPath, vuln, cfg)
	}

	// Step 2: Run go mod tidy
	if !cfg.SkipTidy {
		if err := gomod.ModTidy(moduleDir); err != nil {
			return fmt.Errorf("go mod tidy failed: %w", err)
		}
	}

	// Step 3: Verify the CVE is fixed by rescanning
	result, err := trivy.Scan(goModPath)
	if err != nil {
		return fmt.Errorf("verification scan failed: %w", err)
	}

	// Check if the same CVE still exists
	for _, v := range result.Vulnerabilities {
		if v.VulnerabilityID == vuln.VulnerabilityID && v.PkgName == vuln.PkgName {
			// CVE still present, need to update through direct dep
			fmt.Printf("  ℹ️  CVE still present after update, tracing dependency chain...\n")
			return updateThroughDirectDep(goModPath, vuln, cfg)
		}
	}

	return nil
}

// updateThroughDirectDep finds and updates the direct dependency that imports the vulnerable indirect dep
func updateThroughDirectDep(goModPath string, vuln trivy.Vulnerability, cfg *config.Config) error {
	moduleDir := gomod.GetModuleDir(goModPath)

	// Find which direct dependency imports this indirect one
	directDeps, err := gomod.FindDirectDependencyFor(moduleDir, vuln.PkgName)
	if err != nil {
		return fmt.Errorf("failed to trace dependency chain: %w", err)
	}

	if len(directDeps) == 0 {
		return fmt.Errorf("could not find direct dependency that imports %s", vuln.PkgName)
	}

	directDep := directDeps[0]
	fmt.Printf("  📦 Indirect dep %s is imported by direct dep: %s\n", vuln.PkgName, directDep)

	// Find which version of the direct dep includes the fixed indirect version
	// This is done by checking the module graph
	targetVersion, err := findDirectDepVersionWithFix(moduleDir, directDep, vuln)
	if err != nil {
		// If we can't find a specific version, try updating to latest
		fmt.Printf("  ℹ️  Could not determine specific version, trying latest...\n")
		targetVersion = "latest"
	}

	// Check for major version bump on the direct dep
	parser, err := gomod.NewParser(goModPath)
	if err != nil {
		return fmt.Errorf("failed to parse go.mod: %w", err)
	}

	currentVersion := parser.GetVersion(directDep)
	if targetVersion != "latest" && gomod.IsMajorVersionBump(currentVersion, targetVersion) {
		if !cfg.AllowMajor {
			return fmt.Errorf("major version bump required for %s (%s -> %s), use --allow-major to permit",
				directDep, currentVersion, targetVersion)
		}
	}

	// Update the direct dependency
	fmt.Printf("  🔄 Updating direct dependency %s to %s\n", directDep, targetVersion)
	if err := gomod.GoGet(moduleDir, directDep, targetVersion); err != nil {
		return fmt.Errorf("failed to update %s: %w", directDep, err)
	}

	// Run go mod tidy
	if !cfg.SkipTidy {
		if err := gomod.ModTidy(moduleDir); err != nil {
			return fmt.Errorf("go mod tidy failed: %w", err)
		}
	}

	return nil
}

// findDirectDepVersionWithFix analyzes the module graph to find which version of a direct
// dependency includes the fixed version of the indirect dependency
func findDirectDepVersionWithFix(moduleDir, directDep string, vuln trivy.Vulnerability) (string, error) {
	// Get the module graph
	edges, err := gomod.ModGraph(moduleDir)
	if err != nil {
		return "", err
	}

	// Find all versions of the direct dep that exist in the graph
	// and check which ones depend on a fixed version of the indirect
	var directDepVersions []string
	directDepBase := getBasePath(directDep)

	for _, edge := range edges {
		fromBase := getBasePath(edge.From.Path)
		if fromBase == directDepBase && edge.From.Version != "" {
			directDepVersions = append(directDepVersions, edge.From.Version)
		}
	}

	// For now, we'll return "latest" and let Go's MVS handle it
	// A more sophisticated approach would query the module proxy for versions
	// and check which ones include the fixed indirect version
	_ = directDepVersions // silence unused warning
	return "latest", nil
}

// getBasePath returns the module path without version suffix
func getBasePath(path string) string {
	// Handle paths like github.com/foo/bar/v2
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		if len(last) > 1 && last[0] == 'v' && last[1] >= '0' && last[1] <= '9' {
			return strings.Join(parts[:len(parts)-1], "/")
		}
	}
	return path
}
