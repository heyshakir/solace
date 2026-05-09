package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"solace/internal/osops"
	"gopkg.in/yaml.v3"
)

type HardeningEngine struct {
	osEngine osops.OSEngine
	rules    []Rule
}

// now accepts OSEngine as a parameter.
func NewHardeningEngine(os osops.OSEngine) *HardeningEngine {
	return &HardeningEngine{
		osEngine: os,
		rules:    make([]Rule, 0),
	}
}

// scan the rules directory
func (e *HardeningEngine) LoadRules(dirPath string) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read rules directory %s: %v", dirPath, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			fullPath := filepath.Join(dirPath, entry.Name())
			
			yamlFile, err := os.ReadFile(fullPath)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %v", fullPath, err)
			}

			var rf RuleFile
			if err := yaml.Unmarshal(yamlFile, &rf); err != nil {
				return fmt.Errorf("failed to parse YAML in %s: %v", fullPath, err)
			}

			e.rules = append(e.rules, rf.Rules...)
		}
	}
	return nil
}

// loop for rules.
func (e *HardeningEngine) EvaluateRules() []Result {
	var results []Result

	currentOS := strings.ToLower(e.osEngine.GetOSName())

	for _, rule := range e.rules {
		result := Result{
			RuleID:        rule.ID,
			Title:         rule.Title,
			ExpectedValue: rule.CheckValue,
			Status:        "Skipped", // default
		}

		if strings.ToLower(rule.OS) != currentOS {
			result.Message = fmt.Sprintf("Rule is for %s, skipping on %s", rule.OS, currentOS)
			results = append(results, result)
			continue
		}

		// Important 
		switch rule.CheckType {
		
		case CheckTypeKernelModule:
			isLoaded, err := e.osEngine.CheckKernelModuleLoaded(rule.CheckTarget)
			if err != nil {
				result.Status = "Error"
				result.Message = err.Error()
			} else if isLoaded {
				result.Status = "Failed"
				result.CurrentValue = "loaded"
				result.Message = fmt.Sprintf("VULNERABILITY: Module %s is currently active.", rule.CheckTarget)
			} else {
				result.Status = "Passed"
				result.CurrentValue = "disabled"
				result.Message = fmt.Sprintf("Secure: Module %s is not active.", rule.CheckTarget)
			}

		case CheckTypeMountPoint:
			isSeparate, options, err := e.osEngine.CheckMountPoint(rule.CheckTarget)
			if err != nil {
				result.Status = "Error"
				result.Message = err.Error()
			} else if !isSeparate {
				result.Status = "Failed"
				result.CurrentValue = "Not a separate partition"
				result.Message = fmt.Sprintf("%s is not mounted as a separate partition.", rule.CheckTarget)
			} else {
				requiredOptions := strings.Split(rule.CheckValue, ",")
				missingOptions := []string{}
				
				for _, reqOpt := range requiredOptions {
					if reqOpt == "separate" { continue }
					
					found := false
					for _, actualOpt := range options {
						if actualOpt == reqOpt { found = true; break }
					}
					if !found { missingOptions = append(missingOptions, reqOpt) }
				}

				if len(missingOptions) > 0 {
					result.Status = "Failed"
					result.CurrentValue = strings.Join(options, ",")
					result.Message = fmt.Sprintf("Missing mount options: %s", strings.Join(missingOptions, ", "))
				} else {
					result.Status = "Passed"
					result.CurrentValue = strings.Join(options, ",")
					result.Message = "Partition exists with all required secure mount options."
				}
			}

		default:
			result.Status = "Error"
			result.Message = fmt.Sprintf("Unknown check_type: %s", rule.CheckType)
		}

		results = append(results, result)
	}

	return results
}