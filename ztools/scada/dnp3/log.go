package dnp3

type DNP3Log struct {
	Banner       string `json:"banner,omitempty"`
	SrcAddress   string `json:"src_address,omitempty"`
	DstAddress   string `json:"dst_address,omitempty"`
	FunctionCode int    `json:"function_code,omitempty"`
}
