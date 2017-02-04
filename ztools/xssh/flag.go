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
	CollectUserAuth   bool
	Ciphers           CipherList
}

type HostKeyAlgorithmsList struct {
	Algorithms []string
}

func (hkaList *HostKeyAlgorithmsList) String() string {
	return strings.Join(hkaList.Algorithms, ",")
}

func (hkaList *HostKeyAlgorithmsList) Set(value string) error {
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

func (hkaList *HostKeyAlgorithmsList) Get() []string {
	if len(hkaList.Algorithms) == 0 {
		return supportedHostKeyAlgos
	} else {
		return hkaList.Algorithms
	}
}

type KexAlgorithmsList struct {
	Algorithms []string
}

func (kaList *KexAlgorithmsList) String() string {
	return strings.Join(kaList.Algorithms, ",")
}

func (kaList *KexAlgorithmsList) Set(value string) error {
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

func (kaList *KexAlgorithmsList) Get() []string {
	if len(kaList.Algorithms) == 0 {
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
	for _, inCipher := range strings.Split(value, ",") {
		isValid := false
		for _, knownCipher := range allSupportedCiphers {
			fmt.Printf("Checking %s -- %s\n", inCipher, knownCipher)
			if inCipher == knownCipher {
				isValid = true
				break
			}
		}

		if !isValid {
			return errors.New(fmt.Sprintf(`cipher not supported: "%s"`, inCipher))
		}

		cList.Ciphers = append(cList.Ciphers, inCipher)
	}

	return nil
}

func (cList *CipherList) Get() []string {
	if len(cList.Ciphers) == 0 {
		return defaultCiphers
	} else {
		return cList.Ciphers
	}
}

func init() {
	flag.StringVar(&pkgConfig.ClientID, "xssh-client-id", packageVersion, "Specify the client ID string to use")

	hostKeyAlgUsage := fmt.Sprintf(
		"A comma-separated list of which host key algorithms to support (default \"%s\")",
		strings.Join(supportedHostKeyAlgos, ","),
	)
	flag.Var(&pkgConfig.HostKeyAlgorithms, "xssh-host-key-algorithms", hostKeyAlgUsage)

	kexAlgUsage := fmt.Sprintf(
		"A comma-separated list of which DH key exchange algorithms to support (default \"%s\")",
		strings.Join(supportedKexAlgos, ","),
	)
	flag.Var(&pkgConfig.KexAlgorithms, "xssh-kex-algorithms", kexAlgUsage)

	ciphersUsage := fmt.Sprintf(
		`A comma-separated list of which ciphers to offer (default "%s")`,
		strings.Join(defaultCiphers, ","))
	flag.Var(&pkgConfig.Ciphers, "xssh-ciphers", ciphersUsage)

	flag.BoolVar(&pkgConfig.Verbose, "xssh-verbose", false, "Output additional information.")

	flag.BoolVar(&pkgConfig.CollectUserAuth, "xssh-userauth", false, "Use the 'none' authentication request to see what userauth methods are allowed.")
}
