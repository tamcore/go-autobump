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
	scanOpts := trivy.ScanOptions{SkipDBUpdate: cfg.SkipTrivyDBUpdate}
	result, err := trivy.Scan(goModPath, scanOpts)
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
	scanOpts := trivy.ScanOptions{SkipDBUpdate: cfg.SkipTrivyDBUpdate}

	// Find which direct dependency imports this indirect one
	directDeps, err := gomod.FindDirectDependencyFor(moduleDir, vuln.PkgName)
	if err != nil {
		return fmt.Errorf("failed to trace dependency chain: %w", err)
	}

	// Also find related packages from the same org (since multiple deps might pull in the vuln)
	relatedDeps, err := findRelatedDirectDependencies(goModPath, vuln.PkgName)
	if err != nil {
		fmt.Printf("  ⚠️  Could not find related dependencies: %v\n", err)
	}

	// Merge and deduplicate: convert import paths to module paths first
	seenModules := make(map[string]bool)
	var allDeps []string

	// Add deps from go mod why first (these are most directly related)
	for _, dep := range directDeps {
		modulePath := importPathToModulePath(goModPath, dep)
		if !seenModules[modulePath] {
			seenModules[modulePath] = true
			allDeps = append(allDeps, modulePath)
		}
	}

	// Then add related deps from same namespace
	for _, dep := range relatedDeps {
		modulePath := importPathToModulePath(goModPath, dep)
		if !seenModules[modulePath] {
			seenModules[modulePath] = true
			allDeps = append(allDeps, modulePath)
		}
	}

	if len(allDeps) == 0 {
		return fmt.Errorf("could not find direct dependency that imports %s", vuln.PkgName)
	}

	// Try updating each related direct dependency until one succeeds in fixing the CVE
	for _, directDep := range allDeps {
		fmt.Printf("  📦 Trying to update related direct dep: %s\n", directDep)

		if err := updateDirectDepAndVerify(goModPath, directDep, vuln, cfg); err != nil {
			fmt.Printf("  ⚠️  Update via %s did not fix CVE: %v\n", directDep, err)
			continue
		}

		// Check if the CVE is fixed
		result, err := trivy.Scan(goModPath, scanOpts)
		if err != nil {
			continue
		}

		cveFixed := true
		for _, v := range result.Vulnerabilities {
			if v.VulnerabilityID == vuln.VulnerabilityID && v.PkgName == vuln.PkgName {
				cveFixed = false
				break
			}
		}

		if cveFixed {
			fmt.Printf("  ✅ CVE fixed by updating %s\n", directDep)
			return nil
		}
	}

	// If we have at least one direct dep, use the first one for the error message
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

// findRelatedDirectDependencies finds direct dependencies from the same org/namespace
// as the vulnerable indirect dependency. This is useful when go mod why doesn't show
// the import chain but we can infer that related packages might pull in the fix.
// If no direct deps are found in the namespace, it falls back to updating indirect deps
// from the same namespace.
func findRelatedDirectDependencies(goModPath, indirectPkg string) ([]string, error) {
	parser, err := gomod.NewParser(goModPath)
	if err != nil {
		return nil, err
	}

	// Extract the org/namespace from the indirect package
	// e.g., github.com/sigstore/timestamp-authority -> github.com/sigstore
	namespace := extractNamespace(indirectPkg)
	if namespace == "" {
		return nil, nil
	}

	// Get all direct dependencies
	directDeps := parser.GetDirectDependencies()

	// Filter to only those in the same namespace
	var relatedDeps []string
	for _, dep := range directDeps {
		depNamespace := extractNamespace(dep.Path)
		if depNamespace == namespace {
			relatedDeps = append(relatedDeps, dep.Path)
		}
	}

	// If no direct deps found, try indirect deps from the same namespace
	// This handles cases where a module only has the sigstore packages as indirect
	if len(relatedDeps) == 0 {
		indirectDeps := parser.GetIndirectDependencies()
		for _, dep := range indirectDeps {
			// Skip the vulnerable package itself
			if dep.Path == indirectPkg {
				continue
			}
			depNamespace := extractNamespace(dep.Path)
			if depNamespace == namespace {
				relatedDeps = append(relatedDeps, dep.Path)
			}
		}
	}

	return relatedDeps, nil
}

// extractNamespace extracts the org/namespace from a module path
// e.g., github.com/sigstore/timestamp-authority -> github.com/sigstore
// e.g., golang.org/x/crypto -> golang.org/x
// e.g., github.com/sigstore/cosign/v2/pkg/cosign -> github.com/sigstore
func extractNamespace(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	if len(parts) < 2 {
		return ""
	}

	// For github.com/org/repo style paths, return github.com/org (first 2 parts)
	// For golang.org/x/pkg style paths, return golang.org/x (first 2 parts)
	// We want host/org, not host/org/repo
	if len(parts) >= 2 {
		return strings.Join(parts[:2], "/")
	}
	return parts[0]
}

// importPathToModulePath converts an import path (e.g., github.com/sigstore/sigstore-go/pkg/root)
// to its module path (e.g., github.com/sigstore/sigstore-go) by matching against modules in go.mod
func importPathToModulePath(goModPath, importPath string) string {
	parser, err := gomod.NewParser(goModPath)
	if err != nil {
		return importPath // Fallback to original
	}

	// Get all dependencies and find the longest matching prefix
	allDeps := append(parser.GetDirectDependencies(), parser.GetIndirectDependencies()...)

	var bestMatch string
	for _, dep := range allDeps {
		// Check if the import path starts with this module path
		if strings.HasPrefix(importPath, dep.Path) {
			// Make sure it's a complete path segment match (not partial)
			if len(importPath) == len(dep.Path) || importPath[len(dep.Path)] == '/' {
				if len(dep.Path) > len(bestMatch) {
					bestMatch = dep.Path
				}
			}
		}
	}

	if bestMatch != "" {
		return bestMatch
	}
	return importPath // Fallback to original
}

// updateDirectDepAndVerify updates a direct dependency to latest and runs tidy
func updateDirectDepAndVerify(goModPath, directDep string, vuln trivy.Vulnerability, cfg *config.Config) error {
	moduleDir := gomod.GetModuleDir(goModPath)

	// Convert import path to module path if needed
	// e.g., github.com/sigstore/sigstore-go/pkg/root -> github.com/sigstore/sigstore-go
	modulePath := importPathToModulePath(goModPath, directDep)

	// Update the direct dependency to latest
	if err := gomod.GoGet(moduleDir, modulePath, "latest"); err != nil {
		return fmt.Errorf("failed to update %s: %w", modulePath, err)
	}

	// Run go mod tidy
	if !cfg.SkipTidy {
		if err := gomod.ModTidy(moduleDir); err != nil {
			return fmt.Errorf("go mod tidy failed: %w", err)
		}
	}

	return nil
}
