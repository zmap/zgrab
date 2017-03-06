// Created by extended_key_usage_gen; DO NOT EDIT

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	"encoding/asn1"
)

const (
OID_EKU_EAP_OVER_PPP_ = "1.3.6.1.5.5.7.3.13"
OID_EKU_APPLE_CRYPTO_DEVELOPMENT_ENV_ = "1.2.840.113635.100.4.5.4"
OID_EKU_MICROSOFT_TIMESTAMP_SIGNING_ = "1.3.6.1.4.1.311.10.3.2"
OID_EKU_MICROSOFT_SGC_SERIALIZED_ = "1.3.6.1.4.1.311.10.3.3.1"
OID_EKU_MICROSOFT_ROOT_LIST_SIGNER_ = "1.3.6.1.4.1.311.10.3.9"
OID_EKU_MICROSOFT_ENROLLMENT_AGENT_ = "1.3.6.1.4.1.311.20.2.1"
OID_EKU_APPLE_SOFTWARE_UPDATE_SIGNING_ = "1.2.840.113635.100.4.1.2"
OID_EKU_APPLE_CRYPTO_TIER3_QOS_ = "1.2.840.113635.100.4.6.4"
OID_EKU_MICROSOFT_KEY_RECOVERY_3_ = "1.3.6.1.4.1.311.10.3.11"
OID_EKU_MICROSOFT_CSP_SIGNATURE_ = "1.3.6.1.4.1.311.10.3.16"
OID_EKU_APPLE_CRYPTO_TEST_ENV_ = "1.2.840.113635.100.4.5.3"
OID_EKU_APPLE_CRYPTO_TIER1_QOS_ = "1.2.840.113635.100.4.6.2"
OID_EKU_MICROSOFT_NT5_CRYPTO_ = "1.3.6.1.4.1.311.10.3.6"
OID_EKU_MICROSOFT_LIFETIME_SIGNING_ = "1.3.6.1.4.1.311.10.3.13"
OID_EKU_MICROSOFT_SMART_DISPLAY_ = "1.3.6.1.4.1.311.10.3.15"
OID_EKU_MICROSOFT_SYSTEM_HEALTH_LOOPHOLE_ = "1.3.6.1.4.1.311.47.1.3"
OID_EKU_APPLE_CODE_SIGNING_DEVELOPMENT_ = "1.2.840.113635.100.4.1.1"
OID_EKU_MICROSOFT_DRM_ = "1.3.6.1.4.1.311.10.5.1"
OID_EKU_SBGP_CERT_AA_SERVICE_AUTH_ = "1.3.6.1.5.5.7.3.11"
OID_EKU_EAP_OVER_LAN_ = "1.3.6.1.5.5.7.3.14"
OID_EKU_IPSEC_END_SYSTEM_ = "1.3.6.1.5.5.7.3.5"
OID_EKU_ANY_ = "2.5.29.37.0"
OID_EKU_CODE_SIGNING_ = "1.3.6.1.5.5.7.3.3"
OID_EKU_IPSEC_TUNNEL_ = "1.3.6.1.5.5.7.3.6"
OID_EKU_APPLE_SYSTEM_IDENTITY_ = "1.2.840.113635.100.4.4"
OID_EKU_APPLE_CRYPTO_ENV_ = "1.2.840.113635.100.4.5"
OID_EKU_MICROSOFT_MOBILE_DEVICE_SOFTWARE_ = "1.3.6.1.4.1.311.10.3.14"
OID_EKU_MICROSOFT_ENCRYPTED_FILE_SYSTEM_ = "1.3.6.1.4.1.311.10.3.4"
OID_EKU_MICROSOFT_LICENSE_SERVER_ = "1.3.6.1.4.1.311.10.5.4"
OID_EKU_SERVER_AUTH_ = "1.3.6.1.5.5.7.3.1"
OID_EKU_APPLE_RESOURCE_SIGNING_ = "1.2.840.113635.100.4.1.4"
OID_EKU_MICROSOFT_EFS_RECOVERY_ = "1.3.6.1.4.1.311.10.3.4.1"
OID_EKU_MICROSOFT_DRM_INDIVIDUALIZATION_ = "1.3.6.1.4.1.311.10.5.2"
OID_EKU_MICROSOFT_CA_EXCHANGE_ = "1.3.6.1.4.1.311.21.5"
OID_EKU_MICROSOFT_KERNEL_MODE_CODE_SIGNING_ = "1.3.6.1.4.1.311.61.1.1"
OID_EKU_MICROSOFT_OEM_WHQL_CRYPTO_ = "1.3.6.1.4.1.311.10.3.7"
OID_EKU_MICROSOFT_KEY_RECOVERY_21_ = "1.3.6.1.4.1.311.21.6"
OID_EKU_OCSP_SIGNING_ = "1.3.6.1.5.5.7.3.9"
OID_EKU_APPLE_CODE_SIGNING_ = "1.2.840.113635.100.4.1"
OID_EKU_APPLE_ICHAT_ENCRYPTION_ = "1.2.840.113635.100.4.3"
OID_EKU_EMAIL_PROTECTION_ = "1.3.6.1.5.5.7.3.4"
OID_EKU_MICROSOFT_WHQL_CRYPTO_ = "1.3.6.1.4.1.311.10.3.5"
OID_EKU_MICROSOFT_SYSTEM_HEALTH_ = "1.3.6.1.4.1.311.47.1.1"
OID_EKU_TIME_STAMPING_ = "1.3.6.1.5.5.7.3.8"
OID_EKU_APPLE_CRYPTO_MAINTENANCE_ENV_ = "1.2.840.113635.100.4.5.2"
OID_EKU_APPLE_CRYPTO_QOS_ = "1.2.840.113635.100.4.6"
OID_EKU_DVCS_ = "1.3.6.1.5.5.7.3.10"
OID_EKU_CLIENT_AUTH_ = "1.3.6.1.5.5.7.3.2"
OID_EKU_APPLE_CODE_SIGNING_THIRD_PARTY_ = "1.2.840.113635.100.4.1.3"
OID_EKU_MICROSOFT_QUALIFIED_SUBORDINATE_ = "1.3.6.1.4.1.311.10.3.10"
OID_EKU_MICROSOFT_DOCUMENT_SIGNING_ = "1.3.6.1.4.1.311.10.3.12"
OID_EKU_MICROSOFT_SMARTCARD_LOGON_ = "1.3.6.1.4.1.311.20.2.2"
OID_EKU_IPSEC_USER_ = "1.3.6.1.5.5.7.3.7"
OID_EKU_APPLE_ICHAT_SIGNING_ = "1.2.840.113635.100.4.2"
OID_EKU_MICROSOFT_SERVER_GATED_CRYPTO_ = "1.3.6.1.4.1.311.10.3.3"
OID_EKU_MICROSOFT_EMBEDDED_NT_CRYPTO_ = "1.3.6.1.4.1.311.10.3.8"
OID_EKU_APPLE_CRYPTO_PRODUCTION_ENV_ = "1.2.840.113635.100.4.5.1"
OID_EKU_APPLE_CRYPTO_TIER0_QOS_ = "1.2.840.113635.100.4.6.1"
OID_EKU_APPLE_CRYPTO_TIER2_QOS_ = "1.2.840.113635.100.4.6.3"
OID_EKU_MICROSOFT_CERT_TRUST_LIST_SIGNING_ = "1.3.6.1.4.1.311.10.3.1"
OID_EKU_MICROSOFT_LICENSES_ = "1.3.6.1.4.1.311.10.5.3"
)
var (
oidExtKeyUsageMicrosoftKeyRecovery3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 11}
oidExtKeyUsageMicrosoftCspSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 16}
oidExtKeyUsageAppleSoftwareUpdateSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 2}
oidExtKeyUsageAppleCryptoTier3Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 4}
oidExtKeyUsageMicrosoftNt5Crypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 6}
oidExtKeyUsageAppleCryptoTestEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 3}
oidExtKeyUsageAppleCryptoTier1Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 2}
oidExtKeyUsageMicrosoftSystemHealthLoophole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 3}
oidExtKeyUsageMicrosoftLifetimeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 13}
oidExtKeyUsageMicrosoftSmartDisplay = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 15}
oidExtKeyUsageSbgpCertAaServiceAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 11}
oidExtKeyUsageEapOverLan = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 14}
oidExtKeyUsageIpsecEndSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
oidExtKeyUsageAppleCodeSigningDevelopment = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 1}
oidExtKeyUsageMicrosoftDrm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 1}
oidExtKeyUsageAny = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
oidExtKeyUsageMicrosoftMobileDeviceSoftware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 14}
oidExtKeyUsageMicrosoftEncryptedFileSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}
oidExtKeyUsageMicrosoftLicenseServer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 4}
oidExtKeyUsageCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
oidExtKeyUsageIpsecTunnel = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
oidExtKeyUsageAppleSystemIdentity = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 4}
oidExtKeyUsageAppleCryptoEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5}
oidExtKeyUsageMicrosoftDrmIndividualization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 2}
oidExtKeyUsageMicrosoftCaExchange = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 5}
oidExtKeyUsageMicrosoftKernelModeCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
oidExtKeyUsageServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
oidExtKeyUsageAppleResourceSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 4}
oidExtKeyUsageMicrosoftEfsRecovery = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4, 1}
oidExtKeyUsageOcspSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
oidExtKeyUsageMicrosoftOemWhqlCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 7}
oidExtKeyUsageMicrosoftKeyRecovery21 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 6}
oidExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
oidExtKeyUsageAppleCodeSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1}
oidExtKeyUsageAppleIchatEncryption = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 3}
oidExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
oidExtKeyUsageMicrosoftWhqlCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 5}
oidExtKeyUsageMicrosoftSystemHealth = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 1}
oidExtKeyUsageDvcs = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 10}
oidExtKeyUsageClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
oidExtKeyUsageAppleCryptoMaintenanceEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 2}
oidExtKeyUsageAppleCryptoQos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6}
oidExtKeyUsageMicrosoftDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
oidExtKeyUsageMicrosoftSmartcardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
oidExtKeyUsageIpsecUser = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
oidExtKeyUsageAppleCodeSigningThirdParty = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 3}
oidExtKeyUsageMicrosoftQualifiedSubordinate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 10}
oidExtKeyUsageAppleIchatSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 2}
oidExtKeyUsageMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
oidExtKeyUsageMicrosoftEmbeddedNtCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 8}
oidExtKeyUsageAppleCryptoTier2Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 3}
oidExtKeyUsageMicrosoftCertTrustListSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 1}
oidExtKeyUsageMicrosoftLicenses = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 3}
oidExtKeyUsageAppleCryptoProductionEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 1}
oidExtKeyUsageAppleCryptoTier0Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 1}
oidExtKeyUsageMicrosoftSgcSerialized = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3, 1}
oidExtKeyUsageMicrosoftRootListSigner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}
oidExtKeyUsageMicrosoftEnrollmentAgent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 1}
oidExtKeyUsageEapOverPpp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 13}
oidExtKeyUsageAppleCryptoDevelopmentEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 4}
oidExtKeyUsageMicrosoftTimestampSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 2}
)

var ekuOIDs map[string]asn1.ObjectIdentifier

func init() {
ekuOIDs[OID_EKU_MICROSOFT_LIFETIME_SIGNING_] = oidExtKeyUsageMicrosoftLifetimeSigning
ekuOIDs[OID_EKU_MICROSOFT_SMART_DISPLAY_] = oidExtKeyUsageMicrosoftSmartDisplay
ekuOIDs[OID_EKU_MICROSOFT_SYSTEM_HEALTH_LOOPHOLE_] = oidExtKeyUsageMicrosoftSystemHealthLoophole
ekuOIDs[OID_EKU_IPSEC_END_SYSTEM_] = oidExtKeyUsageIpsecEndSystem
ekuOIDs[OID_EKU_APPLE_CODE_SIGNING_DEVELOPMENT_] = oidExtKeyUsageAppleCodeSigningDevelopment
ekuOIDs[OID_EKU_MICROSOFT_DRM_] = oidExtKeyUsageMicrosoftDrm
ekuOIDs[OID_EKU_SBGP_CERT_AA_SERVICE_AUTH_] = oidExtKeyUsageSbgpCertAaServiceAuth
ekuOIDs[OID_EKU_EAP_OVER_LAN_] = oidExtKeyUsageEapOverLan
ekuOIDs[OID_EKU_ANY_] = oidExtKeyUsageAny
ekuOIDs[OID_EKU_MICROSOFT_LICENSE_SERVER_] = oidExtKeyUsageMicrosoftLicenseServer
ekuOIDs[OID_EKU_CODE_SIGNING_] = oidExtKeyUsageCodeSigning
ekuOIDs[OID_EKU_IPSEC_TUNNEL_] = oidExtKeyUsageIpsecTunnel
ekuOIDs[OID_EKU_APPLE_SYSTEM_IDENTITY_] = oidExtKeyUsageAppleSystemIdentity
ekuOIDs[OID_EKU_APPLE_CRYPTO_ENV_] = oidExtKeyUsageAppleCryptoEnv
ekuOIDs[OID_EKU_MICROSOFT_MOBILE_DEVICE_SOFTWARE_] = oidExtKeyUsageMicrosoftMobileDeviceSoftware
ekuOIDs[OID_EKU_MICROSOFT_ENCRYPTED_FILE_SYSTEM_] = oidExtKeyUsageMicrosoftEncryptedFileSystem
ekuOIDs[OID_EKU_MICROSOFT_KERNEL_MODE_CODE_SIGNING_] = oidExtKeyUsageMicrosoftKernelModeCodeSigning
ekuOIDs[OID_EKU_SERVER_AUTH_] = oidExtKeyUsageServerAuth
ekuOIDs[OID_EKU_APPLE_RESOURCE_SIGNING_] = oidExtKeyUsageAppleResourceSigning
ekuOIDs[OID_EKU_MICROSOFT_EFS_RECOVERY_] = oidExtKeyUsageMicrosoftEfsRecovery
ekuOIDs[OID_EKU_MICROSOFT_DRM_INDIVIDUALIZATION_] = oidExtKeyUsageMicrosoftDrmIndividualization
ekuOIDs[OID_EKU_MICROSOFT_CA_EXCHANGE_] = oidExtKeyUsageMicrosoftCaExchange
ekuOIDs[OID_EKU_MICROSOFT_OEM_WHQL_CRYPTO_] = oidExtKeyUsageMicrosoftOemWhqlCrypto
ekuOIDs[OID_EKU_MICROSOFT_KEY_RECOVERY_21_] = oidExtKeyUsageMicrosoftKeyRecovery21
ekuOIDs[OID_EKU_OCSP_SIGNING_] = oidExtKeyUsageOcspSigning
ekuOIDs[OID_EKU_APPLE_CODE_SIGNING_] = oidExtKeyUsageAppleCodeSigning
ekuOIDs[OID_EKU_APPLE_ICHAT_ENCRYPTION_] = oidExtKeyUsageAppleIchatEncryption
ekuOIDs[OID_EKU_EMAIL_PROTECTION_] = oidExtKeyUsageEmailProtection
ekuOIDs[OID_EKU_MICROSOFT_WHQL_CRYPTO_] = oidExtKeyUsageMicrosoftWhqlCrypto
ekuOIDs[OID_EKU_MICROSOFT_SYSTEM_HEALTH_] = oidExtKeyUsageMicrosoftSystemHealth
ekuOIDs[OID_EKU_TIME_STAMPING_] = oidExtKeyUsageTimeStamping
ekuOIDs[OID_EKU_APPLE_CRYPTO_MAINTENANCE_ENV_] = oidExtKeyUsageAppleCryptoMaintenanceEnv
ekuOIDs[OID_EKU_APPLE_CRYPTO_QOS_] = oidExtKeyUsageAppleCryptoQos
ekuOIDs[OID_EKU_DVCS_] = oidExtKeyUsageDvcs
ekuOIDs[OID_EKU_CLIENT_AUTH_] = oidExtKeyUsageClientAuth
ekuOIDs[OID_EKU_IPSEC_USER_] = oidExtKeyUsageIpsecUser
ekuOIDs[OID_EKU_APPLE_CODE_SIGNING_THIRD_PARTY_] = oidExtKeyUsageAppleCodeSigningThirdParty
ekuOIDs[OID_EKU_MICROSOFT_QUALIFIED_SUBORDINATE_] = oidExtKeyUsageMicrosoftQualifiedSubordinate
ekuOIDs[OID_EKU_MICROSOFT_DOCUMENT_SIGNING_] = oidExtKeyUsageMicrosoftDocumentSigning
ekuOIDs[OID_EKU_MICROSOFT_SMARTCARD_LOGON_] = oidExtKeyUsageMicrosoftSmartcardLogon
ekuOIDs[OID_EKU_APPLE_ICHAT_SIGNING_] = oidExtKeyUsageAppleIchatSigning
ekuOIDs[OID_EKU_MICROSOFT_SERVER_GATED_CRYPTO_] = oidExtKeyUsageMicrosoftServerGatedCrypto
ekuOIDs[OID_EKU_MICROSOFT_EMBEDDED_NT_CRYPTO_] = oidExtKeyUsageMicrosoftEmbeddedNtCrypto
ekuOIDs[OID_EKU_MICROSOFT_LICENSES_] = oidExtKeyUsageMicrosoftLicenses
ekuOIDs[OID_EKU_APPLE_CRYPTO_PRODUCTION_ENV_] = oidExtKeyUsageAppleCryptoProductionEnv
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER0_QOS_] = oidExtKeyUsageAppleCryptoTier0Qos
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER2_QOS_] = oidExtKeyUsageAppleCryptoTier2Qos
ekuOIDs[OID_EKU_MICROSOFT_CERT_TRUST_LIST_SIGNING_] = oidExtKeyUsageMicrosoftCertTrustListSigning
ekuOIDs[OID_EKU_MICROSOFT_ENROLLMENT_AGENT_] = oidExtKeyUsageMicrosoftEnrollmentAgent
ekuOIDs[OID_EKU_EAP_OVER_PPP_] = oidExtKeyUsageEapOverPpp
ekuOIDs[OID_EKU_APPLE_CRYPTO_DEVELOPMENT_ENV_] = oidExtKeyUsageAppleCryptoDevelopmentEnv
ekuOIDs[OID_EKU_MICROSOFT_TIMESTAMP_SIGNING_] = oidExtKeyUsageMicrosoftTimestampSigning
ekuOIDs[OID_EKU_MICROSOFT_SGC_SERIALIZED_] = oidExtKeyUsageMicrosoftSgcSerialized
ekuOIDs[OID_EKU_MICROSOFT_ROOT_LIST_SIGNER_] = oidExtKeyUsageMicrosoftRootListSigner
ekuOIDs[OID_EKU_APPLE_SOFTWARE_UPDATE_SIGNING_] = oidExtKeyUsageAppleSoftwareUpdateSigning
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER3_QOS_] = oidExtKeyUsageAppleCryptoTier3Qos
ekuOIDs[OID_EKU_MICROSOFT_KEY_RECOVERY_3_] = oidExtKeyUsageMicrosoftKeyRecovery3
ekuOIDs[OID_EKU_MICROSOFT_CSP_SIGNATURE_] = oidExtKeyUsageMicrosoftCspSignature
ekuOIDs[OID_EKU_APPLE_CRYPTO_TEST_ENV_] = oidExtKeyUsageAppleCryptoTestEnv
ekuOIDs[OID_EKU_APPLE_CRYPTO_TIER1_QOS_] = oidExtKeyUsageAppleCryptoTier1Qos
ekuOIDs[OID_EKU_MICROSOFT_NT5_CRYPTO_] = oidExtKeyUsageMicrosoftNt5Crypto
}
