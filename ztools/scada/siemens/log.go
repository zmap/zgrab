package siemens

type S7Log struct {
	IsS7               bool   `json:"is_s7"`
	System             string `json:"system,omitempty"`
	Module             string `json:"module,omitempty"`
	PlantId            string `json:"plant_id,omitempty"`
	Copyright          string `json:"copyright,omitempty"`
	SerialNumber       string `json:"serial_number,omitempty"`
	ReservedForOS      string `json:"reserved_for_os,omitempty"`
	ModuleType         string `json:"module_type,omitempty"`
	MemorySerialNumber string `json:"memory_serial_number,omitempty"`
	CpuProfile         string `json:"cpu_profile,omitempty"`
	OEMId              string `json:"oem_id,omitempty"`
	Location           string `json:"location,omitempty"`
	ModuleId           string `json:"module_id,omitempty"`
	Hardware           string `json:"hardware,omitempty"`
	Firmware           string `json:"firmware,omitempty"`
}
