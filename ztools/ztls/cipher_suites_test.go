package ztls

import (
	"testing"
)

func TestChromeCiphersImplemented(t *testing.T) {
	for _, cipherID := range ChromeCiphers {
		supported := cipherIDInCipherList(cipherID, implementedCipherSuites)
		if supported != true {
			t.Errorf("Chrome cipher %d (%s) not supported", cipherID, nameForSuite(cipherID))
		}
	}
}

func TestFirefoxCiphersImplemented(t *testing.T) {
	for _, cipherID := range FirefoxCiphers {
		supported := cipherIDInCipherList(cipherID, implementedCipherSuites)
		if supported != true {
			t.Errorf("Firefox cipher %d (%s) not supported", cipherID, nameForSuite(cipherID))
		}
	}
}

/*
func TestSafariCiphersImplemented(t *testing.T) {
	for _, cipherID := range SafariCiphers {
		supported := cipherIDInCipherList(cipherID, implementedCipherSuites)
		if supported != true {
			t.Errorf("Safari cipher %d (%s) not supported", cipherID, nameForSuite(cipherID))
		}
	}
}
*/
