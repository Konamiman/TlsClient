namespace Konamiman.TlsClient.Enums
{
    internal enum HandshakeExtensionType : ushort
    {
        ServerName = 0,
        MaxFragmentLength = 1,
        SupportedGroups = 10,
        SignatureAlgorithms = 13,
        SupportedVersions = 43,
        Cookie = 44,
        KeyShare = 51
    }
}
