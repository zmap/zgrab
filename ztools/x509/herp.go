// Created by extended_key_usage_gen; DO NOT EDIT

// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	"encoding/asn1"
)

var (
oidMicrosoftNt5Crypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 6}
oidAppleIchatSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 2}
oidMicrosoftMobileDeviceSoftware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 14}
oidAppleCryptoDevelopmentEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 4}
oidEapOverLan = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 14}
oidMicrosoftEfsRecovery = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4, 1}
oidDvcs = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 10}
oidIpsecTunnel = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
oidAppleCodeSigningThirdParty = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 3}
oidAppleCryptoQos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6}
oidMicrosoftCertTrustListSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 1}
oidEapOverPpp = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 13}
oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
oidEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
oidAppleCodeSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1}
oidMicrosoftSmartDisplay = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 15}
oidMicrosoftQualifiedSubordinate = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 10}
oidIpsecUser = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
oidMicrosoftEnrollmentAgent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 1}
oidMicrosoftKernelModeCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
oidAppleCryptoTier2Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 3}
oidMicrosoftDrmIndividualization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 2}
oidCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
oidAppleIchatEncryption = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 3}
oidSbgpCertAaServiceAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 11}
oidMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
oidMicrosoftOemWhqlCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 7}
oidMicrosoftRootListSigner = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 9}
oidMicrosoftSystemHealthLoophole = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 3}
oidAppleSoftwareUpdateSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 2}
oidAppleCryptoTier1Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 2}
oidAppleCryptoTier3Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 4}
oidMicrosoftEncryptedFileSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 4}
oidAppleCryptoTestEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 3}
oidAppleCryptoEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5}
oidMicrosoftLicenses = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 3}
oidClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
oidAppleCryptoTier0Qos = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 6, 1}
oidMicrosoftDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
oidAppleCodeSigningDevelopment = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 1}
oidOcspSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
oidMicrosoftWhqlCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 5}
oidMicrosoftDrm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 1}
oidMicrosoftCaExchange = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 5}
oidMicrosoftSystemHealth = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 47, 1, 1}
oidAppleCryptoProductionEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 1}
oidMicrosoftCspSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 16}
oidMicrosoftKeyRecovery3 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 11}
oidMicrosoftLicenseServer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 5, 4}
oidMicrosoftSmartcardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
oidAny = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
oidAppleSystemIdentity = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 4}
oidAppleCryptoMaintenanceEnv = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 5, 2}
oidMicrosoftTimestampSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 2}
oidMicrosoftKeyRecovery21 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 6}
oidIpsecEndSystem = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
oidTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
oidAppleResourceSigning = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 4, 1, 4}
oidMicrosoftSgcSerialized = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3, 1}
oidMicrosoftLifetimeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 13}
oidMicrosoftEmbeddedNtCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 8}
)
