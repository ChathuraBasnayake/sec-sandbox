package batch

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PackageTarget represents a package to be detonated
type PackageTarget struct {
	Name    string
	Version string
}

func (p PackageTarget) String() string {
	if p.Version != "" {
		return fmt.Sprintf("%s@%s", p.Name, p.Version)
	}
	return p.Name
}

// NPMLockfile represents a simplified view of package-lock.json
type NPMLockfile struct {
	LockfileVersion int `json:"lockfileVersion"`
	
	Packages map[string]struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"packages"`

	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// PNPMLockfile represents a simplified view of pnpm-lock.yaml
type PNPMLockfile struct {
	LockfileVersion string `yaml:"lockfileVersion"`
	Packages        map[string]interface{} `yaml:"packages"`
}

// ParseLockfile reads a lockfile (npm or pnpm) and extracts all unique packages
func ParseLockfile(path string) ([]PackageTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read lockfile: %w", err)
	}

	targetsMap := make(map[string]PackageTarget)

	if strings.HasSuffix(path, "pnpm-lock.yaml") {
		var lockfile PNPMLockfile
		if err := yaml.Unmarshal(data, &lockfile); err != nil {
			return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
		}

		for key := range lockfile.Packages {
			// pnpm package keys look like:
			// /lodash@4.17.21
			// lodash@4.17.21
			// /express@4.18.2(debug@4.3.4)
			
			// Remove leading slash
			name := strings.TrimPrefix(key, "/")
			
			// Remove peer dependency modifiers (anything after parenthesis)
			if idx := strings.Index(name, "("); idx != -1 {
				name = name[:idx]
			}
			
			// Split by @ to separate name and version, but handle scoped packages like @types/node@18.0.0
			version := ""
			idx := strings.LastIndex(name, "@")
			if idx > 0 { // > 0 to skip scoped package prefix '@'
				version = name[idx+1:]
				name = name[:idx]
			}

			if name != "" {
				targetsMap[name] = PackageTarget{Name: name, Version: version}
			}
		}

	} else if strings.HasSuffix(path, "package.json") && !strings.HasSuffix(path, "package-lock.json") {
		// Bare package.json
		var pkgJSON struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(data, &pkgJSON); err != nil {
			return nil, fmt.Errorf("failed to parse package.json: %w", err)
		}

		for name, version := range pkgJSON.Dependencies {
			targetsMap[name] = PackageTarget{Name: name, Version: version}
		}
		for name, version := range pkgJSON.DevDependencies {
			targetsMap[name] = PackageTarget{Name: name, Version: version}
		}

	} else {
		// Default to package-lock.json
		var lockfile NPMLockfile
		if err := json.Unmarshal(data, &lockfile); err != nil {
			return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
		}

		if lockfile.LockfileVersion >= 2 {
			for key, pkg := range lockfile.Packages {
				if key == "" {
					continue
				}

				name := pkg.Name
				if name == "" {
					parts := strings.Split(key, "node_modules/")
					if len(parts) > 1 {
						name = parts[len(parts)-1]
					} else {
						name = key
					}
				}

				name = strings.TrimPrefix(name, "node_modules/")
				targetsMap[name] = PackageTarget{Name: name, Version: pkg.Version}
			}
		} else {
			for name, dep := range lockfile.Dependencies {
				targetsMap[name] = PackageTarget{Name: name, Version: dep.Version}
			}
		}
	}

	// Convert map to slice
	var targets []PackageTarget
	for _, target := range targetsMap {
		targets = append(targets, target)
	}

	return targets, nil
}

