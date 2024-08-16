﻿namespace Konamiman.TlsClient.Enums
{
    public enum AlertCode : byte
    {
        closeNotify = 0,
        unexpectedMessage = 10,
        badRecordMac = 20,
        recordOverflow = 22,
        handshakeFailure = 40,
        badCertificate = 42,
        unsupportedCertificate = 43,
        certificateRevoked = 44,
        certificateExpired = 45,
        certificateUnknown = 46,
        illegalParameter = 47,
        unknownCa = 48,
        accessDenied = 49,
        decodeError = 50,
        decryptError = 51,
        protocolVersion = 70,
        insufficientSecurity = 71,
        internalError = 80,
        inappropriateFallback = 86,
        userCanceled = 90,
        missingExtension = 109,
        unsupportedExtension = 110,
        unrecognizedName = 112,
        badCertificateStatusResponse = 113,
        unknownPskIdentity = 115,
        certificateRequired = 116,
        noApplicationProtocol = 120,
    }
}
