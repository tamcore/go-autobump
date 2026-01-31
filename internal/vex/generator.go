package vex

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tamcore/go-autobump/internal/ai"
	"github.com/tamcore/go-autobump/internal/config"
	"github.com/tamcore/go-autobump/internal/gomod"
	"github.com/tamcore/go-autobump/internal/trivy"
)

// OpenVEXDocument represents an OpenVEX format document
// Compatible with trivy's --vex openvex flag
type OpenVEXDocument struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling"`
	Statements []Statement `json:"statements"`
}

// Statement represents a VEX statement for a specific vulnerability
type Statement struct {
	VulnerabilityID string    `json:"vulnerability"`
	Products        []Product `json:"products"`
	Status          string    `json:"status"`
	Justification   string    `json:"justification,omitempty"`
	ImpactStatement string    `json:"impact_statement,omitempty"`
	Timestamp       string    `json:"timestamp"`
}

// Product represents a product affected by a vulnerability
type Product struct {
	ID          string      `json:"@id"`
	Identifiers Identifiers `json:"identifiers,omitempty"`
}

// Identifiers holds product identification information
type Identifiers struct {
	PURL string `json:"purl,omitempty"`
}

// AIGeneratedJustification represents the AI-generated response
type AIGeneratedJustification struct {
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ImpactStatement string `json:"impact_statement"`
}

// Generate creates a VEX document for unfixed vulnerabilities
func Generate(vulns []trivy.Vulnerability, cfg *config.Config) error {
	if len(vulns) == 0 {
		return nil
	}

	doc := OpenVEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("https://go-autobump/vex/%d", time.Now().Unix()),
		Author:    "go-autobump",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   1,
		Tooling:   "go-autobump",
	}

	var aiClient *ai.Client
	if cfg.AI.APIKey != "" {
		aiClient = ai.NewClient(cfg.AI.APIKey, cfg.AI.Endpoint, cfg.AI.Model)
	}

	for _, vuln := range vulns {
		stmt := Statement{
			VulnerabilityID: vuln.VulnerabilityID,
			Products: []Product{
				{
					ID: vuln.PkgName,
					Identifiers: Identifiers{
						PURL: fmt.Sprintf("pkg:golang/%s@%s", vuln.PkgName, vuln.InstalledVersion),
					},
				},
			},
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}

		// Try to generate AI justification if configured
		if aiClient != nil {
			justification, err := generateAIJustification(aiClient, vuln, cfg.Path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  AI justification failed for %s: %v\n", vuln.VulnerabilityID, err)
				// Fall back to under_investigation
				stmt.Status = "under_investigation"
				stmt.ImpactStatement = "No fix available. Requires manual analysis."
			} else {
				stmt.Status = justification.Status
				stmt.Justification = justification.Justification
				stmt.ImpactStatement = justification.ImpactStatement
			}
		} else {
			// No AI configured, mark as under_investigation
			stmt.Status = "under_investigation"
			stmt.ImpactStatement = fmt.Sprintf("No fix available for %s in %s@%s. Requires manual analysis.",
				vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion)
		}

		doc.Statements = append(doc.Statements, stmt)
	}

	// Write VEX document
	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal VEX document: %w", err)
	}

	if err := os.WriteFile(cfg.VEXOutput, output, 0644); err != nil {
		return fmt.Errorf("failed to write VEX document: %w", err)
	}

	return nil
}

// generateAIJustification uses AI to generate a VEX justification
func generateAIJustification(client *ai.Client, vuln trivy.Vulnerability, modulePath string) (*AIGeneratedJustification, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get dependency chain using go mod why
	modWhyOutput, err := gomod.ModWhy(modulePath, vuln.PkgName)
	if err != nil {
		modWhyOutput = "Unable to determine dependency chain"
	}

	// Generate justification using AI
	response, err := client.GenerateVEXJustification(ctx, vuln.VulnerabilityID, vuln.PkgName, vuln.Description, modWhyOutput)
	if err != nil {
		return nil, err
	}

	// Parse AI response
	var justification AIGeneratedJustification
	if err := json.Unmarshal([]byte(response), &justification); err != nil {
		// If parsing fails, try to extract from the response
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	// Validate status
	validStatuses := map[string]bool{
		"not_affected":        true,
		"affected":            true,
		"fixed":               true,
		"under_investigation": true,
	}
	if !validStatuses[justification.Status] {
		justification.Status = "under_investigation"
	}

	return &justification, nil
}
