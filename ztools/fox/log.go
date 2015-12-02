package fox

type FoxLog struct {
	Banner string `json:"banner,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	HostAddress string `json:"host_address,omitempty"`
	Version string `json:"version,omitempty"`
	AppName string `json:"app_name,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
	VMName string `json:"vm_name,omitempty"`
	VMVersion string `json:"vm_version,omitempty"`
	OSName string `json:"os_name,omitempty"`
	TimeZone string `json:"time_zone,omitempty"`
	HostId string `json:"host_id,omitempty"`
	VMUuid string `json:"vm_uuid,omitempty"`
	BrandId string `json:"BrandId,omitempty"`
}