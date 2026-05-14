package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"strconv"

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
			// result.Message = fmt.Sprintf("Rule is for %s, skipping on %s", rule.OS, currentOS)
			result.Message = "OS mismatch, skipping."
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
		
		// For linux, we will check if critical mount points have secure options like noexec, nodev, nosuid.
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
		
		// For windows, we will use secedit to check security policies.
		case CheckTypeSecedit:
			actualVal, err := e.osEngine.GetSeceditValue(rule.CheckTarget)
			if err != nil {
					result.Status = "Error"
					result.Message = err.Error()
					break
			}
			result.CurrentValue = actualVal
			// For numeric policies, we need to compare integers. For others, we can do string comparison.
			actualInt, _ := strconv.Atoi(actualVal)
			expectedInt, _ := strconv.Atoi(rule.CheckValue)
			passed := false
			if rule.CheckTarget == "PasswordHistorySize" || rule.CheckTarget == "MinimumPasswordLength" || rule.CheckTarget == "LockoutDuration" {
					passed = actualInt >= expectedInt
			} else if rule.CheckTarget == "MaximumPasswordAge" || rule.CheckTarget == "LockoutBadCount" {
					passed = actualInt > 0 && actualInt <= expectedInt
			} else {
					passed = actualInt == expectedInt
			}
			if passed {
					result.Status = "Passed"
                    result.Message = fmt.Sprintf("Policy meets requirement (Current: %s)", actualVal)					
			} else {
					result.Status = "Failed"
					result.Message = fmt.Sprintf("Expected %s, but found %s", rule.CheckValue, actualVal)
			}

		case CheckTypeRegistry:
			// Target format: "PATH|KEY"
			parts := strings.Split(rule.CheckTarget, "|")
			if len(parts) != 2 {
				result.Status = "Error"
				result.Message = "Invalid registry target format"
				break
			}
			actualVal, err := e.osEngine.GetRegistryValue(parts[0], parts[1])
			if err != nil {
                // If registry key doesn't exist, it means policy isn't configured
                result.Status = "Failed"
                result.Status = "Error"
                result.CurrentValue = "Not Set"
                result.Message = "Registry value is not configured"
			} else {
				result.CurrentValue = actualVal
				if actualVal == rule.CheckValue {
					result.Status = "Passed"
					result.Message = fmt.Sprintf("Registry value matches policy (%s)", actualVal)
				} else {
					result.Status = "Failed"
					result.Message = fmt.Sprintf("Expected %s, but found %s", rule.CheckValue, actualVal)
				}
			}

		case CheckTypeService:
			status, err := e.osEngine.CheckServiceStatus(rule.CheckTarget)
			if err != nil {
				result.Status = "Error"
				result.Message = err.Error()
			} else {
				result.CurrentValue = status
				if status == rule.CheckValue || (rule.CheckValue == "disabled" && (status == "stopped" || status == "not_found")) {
					result.Status = "Passed"
					result.Message = fmt.Sprintf("%s Service is %s", rule.CheckTarget, status)
				} else {
					result.Status = "Failed"
					result.Message = fmt.Sprintf("%s Service is %s (Expected: %s)", rule.CheckTarget, status, rule.CheckValue)
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