namespace Konamiman.TlsClient.Enums
{
    public enum RecordContentType : byte
    {
        None = 0,
        ChangeCipherCpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    }
}
