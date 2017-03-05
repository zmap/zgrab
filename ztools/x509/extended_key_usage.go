package x509

import "encoding/asn1"

var (
	// RFC 5280 Section 4.2.1.12 only defines a few EKU OIDs. The rest are taken
	// from VirtualBox (I'm as surprised as you are).
	//
	// See https://www.virtualbox.org/svn/vbox/trunk/include/iprt/crypto/x509.h

	// "Common" OIDs
	oidExtKeyUsageAny                   = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageDVCS                  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 10}
	oidExtKeyUsageSBGPCertAAServiceAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 11}
	oidExtKeyUsageEAPOverPPP            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 13}
	oidExtKeyUsageEAPOverLAN            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 14}

	// Microsoft OIDs
	oidExtKeyUsageMicrosoftCertTrustListSigning  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 1}
	oidExtKeyUsageMicrosoftTimestampSigning      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 2}
	oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageMicrosoftSGCSerialized         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3, 1}
	oidExtKeyUsageMicrosoftEncryptedFileSystem   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}
	oidExtKeyUsageMicrosoftWHQLCrypto            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 5}
	oidExtKeyUsageMicrosoftNT5Crypto             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 6}
	oidExtKeyUsageMicrosoftOEMWHQLCrypto         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 7}
	oidExtKeyUsageMicrosoftEmbeddedNTCrypto      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 8}
	oidExtKeyUsageMicrosoftRootListSigner        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}
	oidExtKeyUsageMicrosoftQualifiedSubordinate  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 10}
	oidExtKeyUsageMicrosoftKeyRecovery3          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 11}
	oidExtKeyUsageMicrosoftDocumentSigning       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
	oidExtKeyUsageMicrosoftLifetimeSigning       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 13}
	oidExtKeyUsageMicrosoftMobileDeviceSoftware  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 14}
	oidExtKeyUsageMicrosoftSmartDisplay          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 15}
	oidExtKeyUsageMicrosoftCSPSignature          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 16}
	oidExtKeyUsageMicrosoftEFSRecovery           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4, 1}
	oidExtKeyUsageMicrosoftDRM                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 1}
	oidExtKeyUsageMicrosoftDRMIndividualization  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 2}
	oidExtKeyUsageMicrosoftLicenses              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 3}
	oidExtKeyUsageMicrosoftLicenseServer         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 4}
	oidExtKeyUsageMicrosoftEnrollmentAgent       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 1}
	oidExtKeyUsageMicrosoftSmartcardLogon        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	oidExtKeyUsageMicrosoftCAExchange            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 5}
	oidExtKeyUsageMicrosoftKeyRecovery21         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 6}
	oidExtKeyUsageMicrosoftSystemHealth          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 1}
	oidExtKeyUsageMicrosoftSystemHealthLoophole  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 3}
	oidExtKeyUsageMicrosoftKernelModeCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}

	// Apple OIDs
	oidExtKeyUsageAppleAppleExtendedKeyUsage  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4}
	oidExtKeyUsageAppleCodeSigning            = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1}
	oidExtKeyUsageAppleCodeSigningDevelopment = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 1}
	oidExtKeyUsageAppleSoftwareUpdateSigning  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 2}
	oidExtKeyUsageAppleCodeSigningThridParty  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 3}
	oidExtKeyUsageAppleResourceSigning        = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 4}
	oidExtKeyUsageAppleIChatSigning           = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 2}
	oidExtKeyUsageAppleIChatEncryption        = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 3}
	oidExtKeyUsageAppleSystemIdentity         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 4}
	oidExtKeyUsageAppleCryptoEnv              = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5}
	oidExtKeyUsageAppleCryptoProductionEnv    = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 1}
	oidExtKeyUsageAppleCryptoMaintenanceEnv   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 2}
	oidExtKeyUsageAppleCryptoTestEnv          = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 3}
	oidExtKeyUsageAppleCryptoDevelopmentEnv   = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 4}
	oidExtKeyUsageAppleCryptoQos              = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6}
	oidExtKeyUsageAppleCryptoTier0QOS         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 1}
	oidExtKeyUsageAppleCryptoTier1QOS         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 2}
	oidExtKeyUsageAppleCryptoTier2QOS         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 3}
	oidExtKeyUsageAppleCryptoTier3QOS         = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 4}
)

var (
	ekuOIDs map[string]asn1.ObjectIdentifier
)

func init() {
	ekuOIDs := make(map[string]asn1.ObjectIdentifier)
	ekuOIDs[oidExtKeyUsageServerAuth.String()] = oidExtKeyUsageServerAuth
	ekuOIDs[oidExtKeyUsageClientAuth.String()] = oidExtKeyUsageClientAuth
	ekuOIDs[oidExtKeyUsageCodeSigning.String()] = oidExtKeyUsageCodeSigning
	ekuOIDs[oidExtKeyUsageEmailProtection.String()] = oidExtKeyUsageEmailProtection
	ekuOIDs[oidExtKeyUsageIPSECEndSystem.String()] = oidExtKeyUsageIPSECEndSystem
	ekuOIDs[oidExtKeyUsageIPSECTunnel.String()] = oidExtKeyUsageIPSECTunnel
	ekuOIDs[oidExtKeyUsageIPSECUser.String()] = oidExtKeyUsageIPSECUser
	ekuOIDs[oidExtKeyUsageTimeStamping.String()] = oidExtKeyUsageTimeStamping
	ekuOIDs[oidExtKeyUsageOCSPSigning.String()] = oidExtKeyUsageOCSPSigning
	ekuOIDs[oidExtKeyUsageDVCS.String()] = oidExtKeyUsageDVCS
	ekuOIDs[oidExtKeyUsageSBGPCertAAServiceAuth.String()] = oidExtKeyUsageSBGPCertAAServiceAuth
	ekuOIDs[oidExtKeyUsageEAPOverPPP.String()] = oidExtKeyUsageEAPOverPPP
	ekuOIDs[oidExtKeyUsageEAPOverLAN.String()] = oidExtKeyUsageEAPOverLAN
	ekuOIDs[oidExtKeyUsageMicrosoftCertTrustListSigning.String()] = oidExtKeyUsageMicrosoftCertTrustListSigning
	ekuOIDs[oidExtKeyUsageMicrosoftTimestampSigning.String()] = oidExtKeyUsageMicrosoftTimestampSigning
	ekuOIDs[oidExtKeyUsageMicrosoftServerGatedCrypto.String()] = oidExtKeyUsageMicrosoftServerGatedCrypto
	ekuOIDs[oidExtKeyUsageMicrosoftSGCSerialized.String()] = oidExtKeyUsageMicrosoftSGCSerialized
	ekuOIDs[oidExtKeyUsageMicrosoftEncryptedFileSystem.String()] = oidExtKeyUsageMicrosoftEncryptedFileSystem
	ekuOIDs[oidExtKeyUsageMicrosoftWHQLCrypto.String()] = oidExtKeyUsageMicrosoftWHQLCrypto
	ekuOIDs[oidExtKeyUsageMicrosoftNT5Crypto.String()] = oidExtKeyUsageMicrosoftNT5Crypto
	ekuOIDs[oidExtKeyUsageMicrosoftOEMWHQLCrypto.String()] = oidExtKeyUsageMicrosoftOEMWHQLCrypto
	ekuOIDs[oidExtKeyUsageMicrosoftEmbeddedNTCrypto.String()] = oidExtKeyUsageMicrosoftEmbeddedNTCrypto
	ekuOIDs[oidExtKeyUsageMicrosoftRootListSigner.String()] = oidExtKeyUsageMicrosoftRootListSigner
	ekuOIDs[oidExtKeyUsageMicrosoftQualifiedSubordinate.String()] = oidExtKeyUsageMicrosoftQualifiedSubordinate
	ekuOIDs[oidExtKeyUsageMicrosoftKeyRecovery3.String()] = oidExtKeyUsageMicrosoftKeyRecovery3
	ekuOIDs[oidExtKeyUsageMicrosoftDocumentSigning.String()] = oidExtKeyUsageMicrosoftDocumentSigning
	ekuOIDs[oidExtKeyUsageMicrosoftLifetimeSigning.String()] = oidExtKeyUsageMicrosoftLifetimeSigning
	ekuOIDs[oidExtKeyUsageMicrosoftMobileDeviceSoftware.String()] = oidExtKeyUsageMicrosoftMobileDeviceSoftware
	ekuOIDs[oidExtKeyUsageMicrosoftSmartDisplay.String()] = oidExtKeyUsageMicrosoftSmartDisplay
	ekuOIDs[oidExtKeyUsageMicrosoftCSPSignature.String()] = oidExtKeyUsageMicrosoftCSPSignature
	ekuOIDs[oidExtKeyUsageMicrosoftEFSRecovery.String()] = oidExtKeyUsageMicrosoftEFSRecovery
	ekuOIDs[oidExtKeyUsageMicrosoftDRM.String()] = oidExtKeyUsageMicrosoftDRM
	ekuOIDs[oidExtKeyUsageMicrosoftDRMIndividualization.String()] = oidExtKeyUsageMicrosoftDRMIndividualization
	ekuOIDs[oidExtKeyUsageMicrosoftLicenses.String()] = oidExtKeyUsageMicrosoftLicenses
	ekuOIDs[oidExtKeyUsageMicrosoftLicenseServer.String()] = oidExtKeyUsageMicrosoftLicenseServer
	ekuOIDs[oidExtKeyUsageMicrosoftEnrollmentAgent.String()] = oidExtKeyUsageMicrosoftEnrollmentAgent
	ekuOIDs[oidExtKeyUsageMicrosoftSmartcardLogon.String()] = oidExtKeyUsageMicrosoftSmartcardLogon
	ekuOIDs[oidExtKeyUsageMicrosoftCAExchange.String()] = oidExtKeyUsageMicrosoftCAExchange
	ekuOIDs[oidExtKeyUsageMicrosoftKeyRecovery21.String()] = oidExtKeyUsageMicrosoftKeyRecovery21
	ekuOIDs[oidExtKeyUsageMicrosoftSystemHealth.String()] = oidExtKeyUsageMicrosoftSystemHealth
	ekuOIDs[oidExtKeyUsageMicrosoftSystemHealthLoophole.String()] = oidExtKeyUsageMicrosoftSystemHealthLoophole
	ekuOIDs[oidExtKeyUsageMicrosoftKernelModeCodeSigning.String()] = oidExtKeyUsageMicrosoftKernelModeCodeSigning
	ekuOIDs[oidExtKeyUsageAppleAppleExtendedKeyUsage.String()] = oidExtKeyUsageAppleAppleExtendedKeyUsage
	ekuOIDs[oidExtKeyUsageAppleCodeSigning.String()] = oidExtKeyUsageAppleCodeSigning
	ekuOIDs[oidExtKeyUsageAppleCodeSigningDevelopment.String()] = oidExtKeyUsageAppleCodeSigningDevelopment
	ekuOIDs[oidExtKeyUsageAppleSoftwareUpdateSigning.String()] = oidExtKeyUsageAppleSoftwareUpdateSigning
	ekuOIDs[oidExtKeyUsageAppleCodeSigningThridParty.String()] = oidExtKeyUsageAppleCodeSigningThridParty
	ekuOIDs[oidExtKeyUsageAppleResourceSigning.String()] = oidExtKeyUsageAppleResourceSigning
	ekuOIDs[oidExtKeyUsageAppleIChatSigning.String()] = oidExtKeyUsageAppleIChatSigning
	ekuOIDs[oidExtKeyUsageAppleIChatEncryption.String()] = oidExtKeyUsageAppleIChatEncryption
	ekuOIDs[oidExtKeyUsageAppleSystemIdentity.String()] = oidExtKeyUsageAppleSystemIdentity
	ekuOIDs[oidExtKeyUsageAppleCryptoEnv.String()] = oidExtKeyUsageAppleCryptoEnv
	ekuOIDs[oidExtKeyUsageAppleCryptoProductionEnv.String()] = oidExtKeyUsageAppleCryptoProductionEnv
	ekuOIDs[oidExtKeyUsageAppleCryptoMaintenanceEnv.String()] = oidExtKeyUsageAppleCryptoMaintenanceEnv
	ekuOIDs[oidExtKeyUsageAppleCryptoTestEnv.String()] = oidExtKeyUsageAppleCryptoTestEnv
	ekuOIDs[oidExtKeyUsageAppleCryptoDevelopmentEnv.String()] = oidExtKeyUsageAppleCryptoDevelopmentEnv
	ekuOIDs[oidExtKeyUsageAppleCryptoQos.String()] = oidExtKeyUsageAppleCryptoQos
	ekuOIDs[oidExtKeyUsageAppleCryptoTier0QOS.String()] = oidExtKeyUsageAppleCryptoTier0QOS
	ekuOIDs[oidExtKeyUsageAppleCryptoTier1QOS.String()] = oidExtKeyUsageAppleCryptoTier1QOS
	ekuOIDs[oidExtKeyUsageAppleCryptoTier2QOS.String()] = oidExtKeyUsageAppleCryptoTier2QOS
	ekuOIDs[oidExtKeyUsageAppleCryptoTier3QOS.String()] = oidExtKeyUsageAppleCryptoTier3QOS
}
