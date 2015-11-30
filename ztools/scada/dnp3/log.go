package dnp3

type DNP3Log struct {
	LinkAddress  string `json:"link_address,omitempty"`
	FunctionCode int    `json:"function_code,omitempty"`
	RawResponse  string `json:"raw_response,omitempty"`
}
