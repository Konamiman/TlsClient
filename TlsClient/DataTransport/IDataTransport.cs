namespace Konamiman.TlsClient.DataTransport;

/// <summary>
/// Represents the underlying data transport layer for a TLS connection,
/// that is, a sequential, reliable and ordered pair of input and output
/// byte streams.
/// </summary>
public interface IDataTransport
{
    /// <summary>
    /// Send a block of data to the output stream.
    /// </summary>
    /// <param name="data">Array containing the block of data to send.</param>
    /// <param name="index">Start index of the block within the array.</param>
    /// <param name="length">Length of the block.</param>
    /// <returns>True on success, false on failure.</returns>
    bool Send(byte[] data, int index = 0, int? length = null);

    /// <summary>
    /// Receive a block of data from the input stream.
    /// </summary>
    /// <param name="destination">Array where the data will be written.</param>
    /// <param name="index">Write start index within the array.</param>
    /// <param name="length">Maximum length of the block to be received.</param>
    /// <returns>Actual length of the received block.</returns>
    int Receive(byte[] destination, int index, int length);

    /// <summary>
    /// Indicates if there's data available to be received from the input stream.
    /// </summary>
    /// <returns></returns>
    bool HasDataToReceive();

    /// <summary>
    /// Indicates if the output stream is closed, meaning that no further data can be sent.
    /// </summary>
    /// <returns></returns>
    bool IsLocallyClosed();

    /// <summary>
    /// Indicates if the input stream is closed, meaning that no further data can be received.
    /// </summary>
    /// <returns></returns>
    bool IsRemotelyClosed();

    /// <summary>
    /// Close the output stream, so that no further data can be sent.
    /// </summary>
    void Close();
}
