package ztls

import (
	"math/big"

	"github.com/zmap/zgrab/ztools/keys"
)

func (ka *dheKeyAgreement) DHParams() *keys.DHParams {
	out := new(keys.DHParams)
	if ka.p != nil {
		out.Prime = new(big.Int).Set(ka.p)
	}
	if ka.g != nil {
		out.Generator = new(big.Int).Set(ka.g)
	}
	if ka.yServer != nil {
		out.ServerPublic = new(big.Int).Set(ka.yServer)
	}
	return out
}
