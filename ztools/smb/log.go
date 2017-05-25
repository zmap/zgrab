package smb

type SMBLog struct {
	IsSMB     bool `json:"is_smb"`
	SupportV1 bool `json:"smbv1"`
}
