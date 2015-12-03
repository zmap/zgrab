package dnp3

type DNP3Log struct {
	IsDNP3		bool `json:"is_dnp3"`
	RawResponse  string `json:"raw_response,omitempty"`
}
