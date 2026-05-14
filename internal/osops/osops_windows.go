package osops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type windowsEngine struct {
	osName       string
	seceditCache map[string]string // caches secpol.inf data to avoid running secedit multiple times
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
	// Simple check by trying to open physical drive
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (w *windowsEngine) GetLogPaths() []string {
	return []string{"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"}
}

func (w *windowsEngine) CheckKernelModuleLoaded(moduleName string) (bool, error) {
	return false, nil
}

func (w *windowsEngine) CheckMountPoint(path string) (bool, []string, error) {
	return false, nil, nil
}

// GetSeceditValue runs secedit to export policies, parses the file, and caches results
func (w *windowsEngine) GetSeceditValue(key string) (string, error) {
	if len(w.seceditCache) == 0 {
		tempDir := os.TempDir()
		infPath := filepath.Join(tempDir, "secpol_audit.inf")

		cmd := exec.Command("secedit", "/export", "/cfg", infPath)
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("secedit export failed: %v", err)
		}

		raw, err := os.ReadFile(infPath)
		if err != nil {
			return "", fmt.Errorf("failed to read secpol.inf: %v", err)
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
					k := strings.TrimSpace(parts[0])
					v := strings.TrimSpace(parts[1])
					w.seceditCache[k] = v
				}
			}
		}
		os.Remove(infPath)
	}

	val, exists := w.seceditCache[key]
	if !exists {
		return "", fmt.Errorf("key not found in security policy")
	}

	return val, nil
}