using System;

namespace Konamiman.TlsClient.DataStructures;

/// <summary>
/// Represents a buffer of byte data to be retrieved in chunks.
/// </summary>
internal class OutputBuffer
{
    private byte[] data = null;

    private int outputPointer = 0;

    private int length = 0;

    private int remaining => length - outputPointer;

    /// <summary>
    /// Indicates if there are no more bytes available to extract.
    /// </summary>
    public bool IsEmpty => outputPointer == length;

    /// <summary>
    /// Initialize the buffer with a set of data.
    /// </summary>
    /// <param name="data"></param>
    public void Initialize(byte[] data)
    {
        this.data = data;
        length = data.Length;
        outputPointer = 0;
    }

    /// <summary>
    /// Extract data from the buffer.
    /// </summary>
    /// <param name="destination">Destination array for the data.</param>
    /// <param name="index">Starting write index in the destination array.</param>
    /// <param name="length">Maximum amount of bytes to extract.</param>
    /// <returns>Actual amount of bytes extracted.</returns>
    public int Extract(byte[] destination, int index, int length)
    {
        if(IsEmpty) return 0;

        length = Math.Min(length, remaining);
        Array.Copy(data, outputPointer, destination, index, length);
        outputPointer += length;
        return length;
    }
}
