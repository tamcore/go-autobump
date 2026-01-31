package gomod

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// Parser handles go.mod file parsing and manipulation
type Parser struct {
	Path    string
	ModFile *modfile.File
}

// NewParser creates a new Parser for the given go.mod file path
func NewParser(goModPath string) (*Parser, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	modFile, err := modfile.Parse(goModPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	return &Parser{
		Path:    goModPath,
		ModFile: modFile,
	}, nil
}

// ModulePath returns the module path from go.mod
func (p *Parser) ModulePath() string {
	if p.ModFile.Module != nil {
		return p.ModFile.Module.Mod.Path
	}
	return ""
}

// IsDirectDependency checks if a package is a direct dependency
func (p *Parser) IsDirectDependency(pkgPath string) bool {
	for _, req := range p.ModFile.Require {
		if req.Mod.Path == pkgPath && !req.Indirect {
			return true
		}
	}
	return false
}

// GetVersion returns the version of a dependency, empty if not found
func (p *Parser) GetVersion(pkgPath string) string {
	for _, req := range p.ModFile.Require {
		if req.Mod.Path == pkgPath {
			return req.Mod.Version
		}
	}
	return ""
}

// GetDirectDependencies returns all direct dependencies
func (p *Parser) GetDirectDependencies() []Dependency {
	var deps []Dependency
	for _, req := range p.ModFile.Require {
		if !req.Indirect {
			deps = append(deps, Dependency{
				Path:    req.Mod.Path,
				Version: req.Mod.Version,
			})
		}
	}
	return deps
}

// GetIndirectDependencies returns all indirect dependencies
func (p *Parser) GetIndirectDependencies() []Dependency {
	var deps []Dependency
	for _, req := range p.ModFile.Require {
		if req.Indirect {
			deps = append(deps, Dependency{
				Path:    req.Mod.Path,
				Version: req.Mod.Version,
			})
		}
	}
	return deps
}

// Dependency represents a Go module dependency
type Dependency struct {
	Path    string
	Version string
}

// ModWhy runs "go mod why -m" to find why a module is needed
// Returns the import chain explaining why the module is required
func ModWhy(moduleDir, pkgPath string) (string, error) {
	cmd := exec.Command("go", "mod", "why", "-m", pkgPath)
	cmd.Dir = moduleDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go mod why failed: %v\nstderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// ModGraph runs "go mod graph" and returns the dependency graph
// Each line is "module@version dependency@version"
func ModGraph(moduleDir string) ([]GraphEdge, error) {
	cmd := exec.Command("go", "mod", "graph")
	cmd.Dir = moduleDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go mod graph failed: %v\nstderr: %s", err, stderr.String())
	}

	var edges []GraphEdge
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		from := parseModuleVersion(parts[0])
		to := parseModuleVersion(parts[1])
		edges = append(edges, GraphEdge{From: from, To: to})
	}

	return edges, nil
}

// GraphEdge represents an edge in the module dependency graph
type GraphEdge struct {
	From ModuleVersion
	To   ModuleVersion
}

// ModuleVersion represents a module path and version
type ModuleVersion struct {
	Path    string
	Version string
}

// parseModuleVersion parses "module@version" or "module" format
func parseModuleVersion(s string) ModuleVersion {
	if idx := strings.LastIndex(s, "@"); idx != -1 {
		return ModuleVersion{
			Path:    s[:idx],
			Version: s[idx+1:],
		}
	}
	return ModuleVersion{Path: s}
}

// FindDirectDependencyFor finds which direct dependency imports the given indirect package
func FindDirectDependencyFor(moduleDir, indirectPkg string) ([]string, error) {
	whyOutput, err := ModWhy(moduleDir, indirectPkg)
	if err != nil {
		return nil, err
	}

	// Parse the output to find direct dependencies in the chain
	// Format:
	// # github.com/indirect/pkg
	// github.com/my/module
	// github.com/direct/dep
	// github.com/indirect/pkg

	lines := strings.Split(whyOutput, "\n")
	var directDeps []string
	seenRoot := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip the main module
		if !seenRoot {
			seenRoot = true
			continue
		}

		// The next non-empty line after the root module is the direct dependency
		// that brings in the indirect one (potentially through a chain)
		directDeps = append(directDeps, line)
		break
	}

	return directDeps, nil
}

// ModTidy runs "go mod tidy" in the module directory
func ModTidy(moduleDir string) error {
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = moduleDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go mod tidy failed: %v\nstderr: %s", err, stderr.String())
	}

	return nil
}

// GetModuleDir returns the directory containing the go.mod file
func GetModuleDir(goModPath string) string {
	return filepath.Dir(goModPath)
}

// GoGet updates a dependency to a specific version
func GoGet(moduleDir, pkgPath, version string) error {
	// Normalize version to ensure it has 'v' prefix for semver
	version = NormalizeVersion(version)

	target := pkgPath + "@" + version
	cmd := exec.Command("go", "get", target)
	cmd.Dir = moduleDir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go get %s failed: %v\nstderr: %s", target, err, stderr.String())
	}

	return nil
}

// IsMajorVersionBump checks if updating from oldVersion to newVersion is a major version bump
// This includes cases where the module path would need to change (e.g., /v2)
func IsMajorVersionBump(oldVersion, newVersion string) bool {
	oldMajor := extractMajor(oldVersion)
	newMajor := extractMajor(newVersion)

	return newMajor > oldMajor
}

// extractMajor extracts the major version number from a semver string
func extractMajor(version string) int {
	// Strip v prefix
	version = strings.TrimPrefix(version, "v")

	// Get first part before dot
	if idx := strings.Index(version, "."); idx != -1 {
		version = version[:idx]
	}

	var major int
	_, _ = fmt.Sscanf(version, "%d", &major)
	return major
}

// NormalizeVersion ensures the version string has the proper format for Go modules.
// It adds a 'v' prefix if missing and the version looks like semver (e.g., "1.2.3" -> "v1.2.3").
// Special versions like "latest" are returned unchanged.
func NormalizeVersion(version string) string {
	// Don't modify special versions
	if version == "latest" || version == "" {
		return version
	}

	// If it already has a 'v' prefix, return as-is
	if strings.HasPrefix(version, "v") {
		return version
	}

	// Check if it looks like a semver (starts with a digit)
	if len(version) > 0 && version[0] >= '0' && version[0] <= '9' {
		return "v" + version
	}

	return version
}

// HasMajorVersionModule checks if the go.mod already has a major version variant of the module.
// For example, if vulnPkg is "github.com/foo/bar" (v1) and fixedVersion is "2.0.0",
// this checks if "github.com/foo/bar/v2" exists in go.mod.
// Go modules v2+ use semantic import versioning where the major version is part of the path.
// Returns (hasMajorVersion, majorVersionVersion, vulnModuleStillPresent)
func (p *Parser) HasMajorVersionModule(vulnPkg, fixedVersion string) (bool, string, bool) {
	fixedMajor := extractMajor(fixedVersion)
	if fixedMajor < 2 {
		return false, "", false
	}

	// Strip any existing version suffix from the package path (e.g., /v2, /v3)
	basePath := stripMajorVersionSuffix(vulnPkg)

	// Check if the target major version module exists
	targetPath := fmt.Sprintf("%s/v%d", basePath, fixedMajor)

	var hasMajorVersion bool
	var majorVersionVersion string
	var vulnModuleStillPresent bool

	for _, req := range p.ModFile.Require {
		if req.Mod.Path == targetPath {
			hasMajorVersion = true
			majorVersionVersion = req.Mod.Version
		}
		// Check if the vulnerable v1 module is still present
		if req.Mod.Path == vulnPkg {
			vulnModuleStillPresent = true
		}
	}

	return hasMajorVersion, majorVersionVersion, vulnModuleStillPresent
}

// stripMajorVersionSuffix removes /v2, /v3, etc. from a module path
func stripMajorVersionSuffix(path string) string {
	// Check for /vN suffix where N >= 2
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		return path
	}

	suffix := path[lastSlash+1:]
	if len(suffix) >= 2 && suffix[0] == 'v' && suffix[1] >= '2' && suffix[1] <= '9' {
		// Verify it's just digits after 'v'
		allDigits := true
		for _, c := range suffix[1:] {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return path[:lastSlash]
		}
	}

	return path
}
