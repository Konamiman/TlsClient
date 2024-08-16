namespace Konamiman.TlsClient.Enums
{
    public enum HandshakeType : byte
    {
        None = 0,
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        EncryptedExtensions = 8,
        Certificate = 11,
        CertificateRequest = 13,
        CertificateVerify = 15,
        Finished = 20,
        KeyUpdate = 24
    }
}
