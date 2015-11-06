package iscsi

type ISCSIConfig struct {
	ISCSI          bool
	LocalLogin     string
	MaxConnections int
}
