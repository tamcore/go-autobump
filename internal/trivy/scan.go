package trivy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

// ScanOptions configures the trivy scan behavior
type ScanOptions struct {
	SkipDBUpdate bool
}

// Scan runs Trivy against the go.mod file
// and returns parsed vulnerability results
func Scan(goModPath string, opts ...ScanOptions) (ScanResult, error) {
	// Build trivy command arguments
	args := []string{
		"fs",
		"--format", "json",
		"--scanners", "vuln",
		"--pkg-types", "library",
	}

	// Check if we should skip DB update
	if len(opts) > 0 && opts[0].SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}

	// Scan the go.mod file directly, not the directory
	// This prevents picking up vulnerabilities from nested go.mod files
	args = append(args, goModPath)

	cmd := exec.Command("trivy", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Trivy returns non-zero exit code when vulnerabilities are found
		// So we only fail if there's no output
		if stdout.Len() == 0 {
			return ScanResult{}, fmt.Errorf("trivy scan failed: %v\nstderr: %s", err, stderr.String())
		}
	}

	// Parse JSON output
	var output TrivyOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return ScanResult{}, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Convert to our internal format
	return convertTrivyOutput(output, goModPath)
}

// convertTrivyOutput transforms Trivy's JSON output into our internal ScanResult format
func convertTrivyOutput(output TrivyOutput, goModPath string) (ScanResult, error) {
	result := ScanResult{
		Target: goModPath,
	}

	// Build a map of package names to their indirect status
	packageIndirect := make(map[string]bool)

	for _, trivyResult := range output.Results {
		// Only process Go module results
		if trivyResult.Type != "gomod" {
			continue
		}

		// Map package indirect status
		for _, pkg := range trivyResult.Packages {
			packageIndirect[pkg.Name] = pkg.Indirect
		}

		// Convert vulnerabilities
		for _, trivyVuln := range trivyResult.Vulnerabilities {
			vuln := Vulnerability{
				VulnerabilityID:  trivyVuln.VulnerabilityID,
				PkgName:          trivyVuln.PkgName,
				InstalledVersion: trivyVuln.InstalledVersion,
				FixedVersion:     trivyVuln.FixedVersion,
				Severity:         trivyVuln.Severity,
				Title:            trivyVuln.Title,
				Description:      trivyVuln.Description,
				PrimaryURL:       trivyVuln.PrimaryURL,
				CVSS:             trivyVuln.CVSS,
				Indirect:         packageIndirect[trivyVuln.PkgName],
				CVSSScore:        getHighestCVSSScore(trivyVuln.CVSS),
			}

			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	return result, nil
}

// getHighestCVSSScore extracts the highest CVSS v3 score from available sources
func getHighestCVSSScore(cvssMap map[string]CVSS) float64 {
	var highest float64

	for _, cvss := range cvssMap {
		if cvss.V3Score > highest {
			highest = cvss.V3Score
		}
	}

	return highest
}
