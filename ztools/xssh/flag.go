package xssh

import (
	"errors"
	"flag"
	"fmt"
	"strings"
)

var pkgConfig XSSHConfig

type XSSHConfig struct {
	ClientID          string
	HostKeyAlgorithms HostKeyAlgorithmsList
	KexAlgorithms     KexAlgorithmsList
	Verbose           bool
	Ciphers           CipherList
}

type HostKeyAlgorithmsList struct {
	IsSet      bool
	Algorithms []string
}

func (hkaList *HostKeyAlgorithmsList) String() string {
	return "BROKEN HostKeyAlgorithmsList.String()"
}

func (hkaList *HostKeyAlgorithmsList) Set(value string) error {
	hkaList.IsSet = true
	for _, alg := range strings.Split(value, ",") {
		isValid := false
		for _, val := range supportedHostKeyAlgos {
			if val == alg {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`Can not support host key algorithm : "%s"`, alg))
		}

		hkaList.Algorithms = append(hkaList.Algorithms, alg)
	}
	return nil
}

func (hkaList *HostKeyAlgorithmsList) GetStringSlice() []string {
	if !hkaList.IsSet {
		return supportedHostKeyAlgos
	} else {
		return hkaList.Algorithms
	}
}

type KexAlgorithmsList struct {
	IsSet      bool
	Algorithms []string
}

func (kaList *KexAlgorithmsList) String() string {
	return "BROKEN HostKeyAlgorithmsList.String()"
}

func (kaList *KexAlgorithmsList) Set(value string) error {
	kaList.IsSet = true
	for _, alg := range strings.Split(value, ",") {
		isValid := false
		for _, val := range supportedKexAlgos {
			if val == alg {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`Can not support DH key exchange algorithm : "%s"`, alg))
		}

		kaList.Algorithms = append(kaList.Algorithms, alg)
	}
	return nil
}

func (kaList *KexAlgorithmsList) GetStringSlice() []string {
	if !kaList.IsSet {
		return supportedKexAlgos
	} else {
		return kaList.Algorithms
	}
}

type CipherList struct {
	Ciphers []string
}

func (cList *CipherList) String() string {
	return strings.Join(cList.Ciphers, ",")
}

func (cList *CipherList) Set(value string) error {
	for _, cipher := range strings.Split(value, ",") {
		isValid := false
		for knownCipher := range cipherModes {
			if cipher == knownCipher {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf("Can not support cipher : %s", cipher))
		}

		cList.Ciphers = append(cList.Ciphers, cipher)
	}

	return nil
}

func (cList *CipherList) Get() []string {
	if len(cList.Ciphers) == 0 {
		return supportedCiphers
	} else {
		return cList.Ciphers
	}
}

func init() {
	flag.StringVar(&pkgConfig.ClientID, "xssh-client-id", packageVersion, "Specify the client ID string to use")

	hostKeyAlgUsage := fmt.Sprintf(
		"A comma-separated list of which host key algorithms to offer (default \"%s\")",
		strings.Join(supportedHostKeyAlgos, ","),
	)
	flag.Var(&pkgConfig.HostKeyAlgorithms, "xssh-host-key-algorithms", hostKeyAlgUsage)

	kexAlgUsage := fmt.Sprintf(
		"A comma-separated list of which DH key exchange algorithms to offer (default \"%s\")",
		strings.Join(supportedKexAlgos, ","),
	)
	flag.Var(&pkgConfig.KexAlgorithms, "xssh-kex-algorithms", kexAlgUsage)

	ciphersUsage := fmt.Sprintf(
		"A comma-separated list of which cipher algorithms to offer (default \"%s\")",
		strings.Join(defaultCiphers, ","),
	)
	flag.Var(&pkgConfig.Ciphers, "xssh-ciphers", ciphersUsage)

	flag.BoolVar(&pkgConfig.Verbose, "xssh-verbose", false, "Output additional information.")
}
