package opcua

type OPCUALog struct {
		IsOPCUA	   bool	  `json:"is_opcua"`
		SecurityPolicyUri string `json:"SecurityPolicyUri,omitempty"`
		ServerProtocolVersion string `json:"ServerProtocolVersion,omitempty"`
		ServerNonce string `json:"ServerNonce,omitempty"`
		ApplicationUri string `json:"ApplicationUri,omitempty"`
		ProductUri string `json:"ProductUri,omitempty"`
		Text string `json:"Text,omitempty"`
		ApplicationType string `json:"ApplicationType,omitempty"`
		GatewayServerUri string `json:"GatewayServerUri,omitempty"`
		DiscoveryProileUri string `json:"DiscoveryProileUri,omitempty"`
		DiscoveryUrl string `json:"DiscoveryUrl,omitempty"`
	}
