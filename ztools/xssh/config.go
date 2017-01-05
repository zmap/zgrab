package xssh

func MakeXSSHConfig() *ClientConfig {
	ret := new(ClientConfig)
	ret.DontAuthenticate = true // IOT scan ethically, never attempt to authenticate
	ret.ClientVersion = pkgConfig.ClientID
	ret.HostKeyAlgorithms = pkgConfig.HostKeyAlgorithms.GetStringSlice()
	ret.KeyExchanges = pkgConfig.KexAlgorithms.GetStringSlice()
	return ret
}
