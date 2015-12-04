package siemens

type S7Log struct {
	IsS7        bool   `json:"is_s7"`
	RawResponse []byte `json:"raw_response,omitempty"`
}
