package zlib

type FTPBannerEvent struct {
	Banner string `json:"banner",omitempty`
}

var FTPBannerEventType = EventType{
	TypeName:         CONNECTION_EVENT_FTP,
	GetEmptyInstance: func() EventData { return new(FTPBannerEvent) },
}

func (f *FTPBannerEvent) GetType() EventType {
	return FTPBannerEventType
}
