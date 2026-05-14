package osops

// import (
// 	"errors"
// )

type OSEngine interface {
	GetOSName() string
	CheckPrivileges() (bool, error)
	GetLogPaths() []string

	// Common
	CheckServiceStatus(serviceName string) (string, error) // Returns "running", "stopped", "not_found"

	// linux specific
	CheckKernelModuleLoaded(moduleName string) (bool, error)
	CheckMountPoint(path string) (isSeparate bool, options []string, err error)

	// windows specific
	GetSeceditValue(key string) (string, error)
	GetRegistryValue(path string, key string) (string, error)

}

// var ErrUnsupportedOS = errors.New("unsupported operating system")