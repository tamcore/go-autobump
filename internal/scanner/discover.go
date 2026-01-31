package scanner

import (
	"os"
	"path/filepath"
)

// DiscoverGoModFiles recursively searches for all go.mod files under the given path
// excludePatterns is a list of glob patterns to exclude (matched against relative paths)
func DiscoverGoModFiles(root string, excludePatterns ...string) ([]string, error) {
	var goModFiles []string

	// Convert to absolute path
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	err = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories and common non-project directories
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" || (len(name) > 0 && name[0] == '.') {
				return filepath.SkipDir
			}
			return nil
		}

		// Check for go.mod files
		if d.Name() == "go.mod" {
			// Get relative path for pattern matching
			relPath, err := filepath.Rel(absRoot, path)
			if err != nil {
				relPath = path
			}

			// Check if path matches any exclude pattern
			excluded := false
			for _, pattern := range excludePatterns {
				if matched, _ := filepath.Match(pattern, relPath); matched {
					excluded = true
					break
				}
				// Also try matching against the directory path
				dirPath := filepath.Dir(relPath)
				if matched, _ := filepath.Match(pattern, dirPath); matched {
					excluded = true
					break
				}
			}

			if !excluded {
				goModFiles = append(goModFiles, path)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return goModFiles, nil
}

// GetModuleDir returns the directory containing the go.mod file
func GetModuleDir(goModPath string) string {
	return filepath.Dir(goModPath)
}
