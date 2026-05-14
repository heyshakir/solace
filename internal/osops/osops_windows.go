package osops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type windowsEngine struct {
	osName       string
	seceditCache map[string]string
}

func NewEngine() (OSEngine, error) {
	return &windowsEngine{
		osName:       "Windows",
		seceditCache: make(map[string]string),
	}, nil
}

func (w *windowsEngine) GetOSName() string {
	return w.osName
}

func (w *windowsEngine) CheckPrivileges() (bool, error) {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (w *windowsEngine) GetLogPaths() []string {
	return []string{"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"}
}

func (w *windowsEngine) CheckServiceStatus(name string) (string, error) {
	// Using sc query to check service state
	out, err := exec.Command("sc", "query", name).Output()
	if err != nil {
		if strings.Contains(err.Error(), "1060") { // Service does not exist
			return "not_found", nil
		}
		return "", err
	}
	strOut := string(out)
	if strings.Contains(strOut, "RUNNING") {
		return "running", nil
	}
	return "stopped", nil
}

func (w *windowsEngine) GetRegistryValue(path string, key string) (string, error) {
	// Logic to handle HKLM vs HKCU
	root := registry.LOCAL_MACHINE
	if strings.HasPrefix(path, "HKCU") {
		root = registry.CURRENT_USER
		path = strings.TrimPrefix(path, "HKCU\\")
	} else {
		path = strings.TrimPrefix(path, "HKLM\\")
	}

	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(key)
	if err != nil {
		// Try string value if integer fails
		sVal, _, err := k.GetStringValue(key)
		if err != nil {
			return "", err
		}
		return sVal, nil
	}
	return fmt.Sprintf("%d", val), nil
}

func (w *windowsEngine) GetSeceditValue(key string) (string, error) {
	if len(w.seceditCache) == 0 {
		tempDir := os.TempDir()
		infPath := filepath.Join(tempDir, "secpol_audit.inf")
		exec.Command("secedit", "/export", "/cfg", infPath).Run()
		raw, err := os.ReadFile(infPath)
		if err != nil {
			return "", err
		}
		var asciiBuf []byte
		for i := 0; i < len(raw); i++ {
			if raw[i] != 0 {
				asciiBuf = append(asciiBuf, raw[i])
			}
		}
		lines := strings.Split(string(asciiBuf), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "=") && !strings.HasPrefix(line, "[") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					w.seceditCache[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
		os.Remove(infPath)
	}
	val, exists := w.seceditCache[key]
	if !exists {
		return "", fmt.Errorf("not found")
	}
	return val, nil
}

func (w *windowsEngine) CheckKernelModuleLoaded(name string) (bool, error) { return false, nil }
func (w *windowsEngine) CheckMountPoint(path string) (bool, []string, error) { return false, nil, nil }