package trivy

// FilterByCVSS filters vulnerabilities by minimum CVSS score threshold
func FilterByCVSS(result ScanResult, threshold float64) ScanResult {
	filtered := ScanResult{
		Target: result.Target,
	}

	for _, vuln := range result.Vulnerabilities {
		if vuln.CVSSScore >= threshold {
			filtered.Vulnerabilities = append(filtered.Vulnerabilities, vuln)
		}
	}

	return filtered
}

// SplitByType separates vulnerabilities into direct and indirect dependencies
func SplitByType(vulns []Vulnerability) (direct, indirect []Vulnerability) {
	for _, vuln := range vulns {
		if vuln.Indirect {
			indirect = append(indirect, vuln)
		} else {
			direct = append(direct, vuln)
		}
	}
	return direct, indirect
}

// HasFixedVersion returns true if the vulnerability has a known fixed version
func HasFixedVersion(vuln Vulnerability) bool {
	return vuln.FixedVersion != ""
}

// GroupByPackage groups vulnerabilities by package name
func GroupByPackage(vulns []Vulnerability) map[string][]Vulnerability {
	grouped := make(map[string][]Vulnerability)

	for _, vuln := range vulns {
		grouped[vuln.PkgName] = append(grouped[vuln.PkgName], vuln)
	}

	return grouped
}
