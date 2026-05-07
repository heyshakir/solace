package osops

import (
	"errors"
)

type OSEngine interface {
	GetOSName() string
	CheckPrivileges() (bool, error)
	GetLogPaths() []string

	// linux specific
	CheckKernelModuleLoaded(moduleName string) (bool, error)
	CheckMountPoint(path string) (isSeparate bool, options []string, err error)
}

var ErrUnsupportedOS = errors.New("operating system not supported by this toolkit")