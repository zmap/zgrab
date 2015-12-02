package fox

type FoxLog struct {
	IsFox         bool   `json:"is_fox"`
	Version       string `json:"version"`
	Id            uint32 `json:"id"`
	Hostname      string `json:"hostname,omitempty"`
	HostAddress   string `json:"host_address,omitempty"`
	AppName       string `json:"app_name,omitempty"`
	AppVersion    string `json:"app_version,omitempty"`
	VMName        string `json:"vm_name,omitempty"`
	VMVersion     string `json:"vm_version,omitempty"`
	OSName        string `json:"os_name,omitempty"`
	OSVersion     string `json:"os_version,omitempty"`
	StationName   string `json:"station_name,omitempty"`
	Language      string `json:"language,omitempty"`
	TimeZone      string `json:"time_zone,omitempty"`
	HostId        string `json:"host_id,omitempty"`
	VMUuid        string `json:"vm_uuid,omitempty"`
	BrandId       string `json:"brand_id,omitempty"`
	SysInfo       string `json:"sys_info,omitempty"`
	AuthAgentType string `json:"auth_agent_type,omitempty"`
}
