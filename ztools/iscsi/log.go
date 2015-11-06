package iscsi

type Target struct {
	Name         string `json:"target_name,omitempty"`
	Address      string `json:"target_address,omitempty"`
	AuthDisabled bool   `json:"authentication_disabled"`
	HadError     bool   `json:"had_error"`
}

type AuthLog struct {
	Destination string   `json:"ip,omitempty"`
	Targets     []Target `json:"targets,omitempty"`
	HadError    bool     `json:"had_error"`
}
