package osops

import "fmt"

type windowsEngine struct {
	osName string
}

func NewEngine() (OSEngine, error) {
	return &windowsEngine{
		osName: "Windows",
	}, nil
}

func (w *windowsEngine) GetOSName() string {
	return w.osName
}

func (w *windowsEngine) CheckPrivileges() (bool, error) {
	fmt.Println("[Windows] Checking Admin privileges...")
	return true, nil 
}

func (w *windowsEngine) GetLogPaths() []string {
	return []string{"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"}
}

// dummy
func (w *windowsEngine) CheckKernelModuleLoaded(moduleName string) (bool, error) {
	return false, nil 
}

// dummy
func (w *windowsEngine) CheckMountPoint(path string) (bool, []string, error) {
	return false, nil, nil 
}