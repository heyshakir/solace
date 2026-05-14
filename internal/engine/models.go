package engine

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string    `json:"id" yaml:"id"`
	Title       string    `json:"title" yaml:"title"`
	Description string    `json:"description" yaml:"description"`
	OS          string    `json:"os" yaml:"os"`
	Severity    string    `json:"severity" yaml:"severity"`
	Category    string    `json:"category" yaml:"category"`

	CheckType   CheckType `json:"check_type" yaml:"check_type"`
	CheckTarget string    `json:"check_target" yaml:"check_target"`
	CheckValue  string    `json:"check_value" yaml:"check_value"`
}

type Result struct {
	RuleID        string `json:"rule_id"`
	Title         string `json:"title"`
	Status        string `json:"status"` // pass, fail, error, skipped
	CurrentValue  string `json:"current_value"`
	ExpectedValue string `json:"expected_value"`
	Message       string `json:"message"`
}

type CheckType string

const (
	CheckTypeKernelModule CheckType = "kernel_module"
	CheckTypeMountPoint   CheckType = "mount_point"
	CheckTypeSysctl       CheckType = "sysctl"
	CheckTypeFileRegex    CheckType = "file_regex"
	CheckTypeFilePerm     CheckType = "file_perm"

	// windows specific
	CheckTypeSecedit      CheckType = "secedit"
	CheckTypeRegistry     CheckType = "registry" // windows registry

	// service and command checks (generic, can be implemented per OS)
	CheckTypeService      CheckType = "service"
	CheckTypeCommand      CheckType = "command"
)