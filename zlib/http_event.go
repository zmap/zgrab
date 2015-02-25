package zlib

type HTTPGETEvent struct {
	Headers []string `json:"headers"`
	Body    string   `json:"body"`
}

var HTTPGetEventType = EventType{
	TypeName:         "http_get",
	GetEmptyInstance: func() EventData { return new(HTTPGETEvent) },
}

func (h *HTTPGETEvent) GetType() EventType {
	return HTTPGetEventType
}
