using System;
using System.Collections.Generic;
using System.Linq;

namespace Konamiman.TlsClient;

/// <summary>
/// Utility methods for numbers and byte arrays.
/// </summary>
internal static class NumberAndArrayUtils
{
    /// <summary>
    /// Converts a 16 bit number to a big endian 2 byte array.
    /// </summary>
    /// <param name="number">The number to convert.</param>
    /// <returns>The resulting array.</returns>
    public static byte[] ToBigEndianUint16Bytes(this ushort number)
    {
        if(BitConverter.IsLittleEndian)
        {
            return BitConverter.GetBytes(number).Reverse().ToArray();
        }
        else
        {
            return BitConverter.GetBytes(number);
        }
    }

    /// <summary>
    /// Converts a 16 bit number to a big endian 2 byte array.
    /// </summary>
    /// <param name="number">The number to convert.</param>
    /// <returns>The resulting array.</returns>
    public static byte[] ToBigEndianUint16Bytes(this int number)
    {
        return ((ushort)number).ToBigEndianUint16Bytes();
    }

    /// <summary>
    /// Converts a 16 bit number to a big endian 3 byte array.
    /// </summary>
    /// <param name="number">The number to convert.</param>
    /// <returns>The resulting array.</returns>
    public static byte[] ToBigEndianUint24Bytes(this int number)
    {
        if (BitConverter.IsLittleEndian)
        {
            return BitConverter.GetBytes(number).Take(3).Reverse().ToArray();
        }
        else
        {
            return BitConverter.GetBytes(number).Skip(1).ToArray();
        }
    }

    /// <summary>
    /// Converts an array of numbers to an array of 2 byte big endian arrays, and returns the concatenated result.
    /// Example: [0x0102, 0x0304, 0x0506] => [1, 2, 3, 4, 5, 6]
    /// </summary>
    /// <param name="numbers">The numbers to convert.</param>
    /// <returns>The numbers converted as explained.</returns>
    public static byte[] ToBigEndianUint16BytesArray(this IEnumerable<ushort> numbers)
    {
        if(BitConverter.IsLittleEndian) {
            return numbers.SelectMany(n => BitConverter.GetBytes((ushort)n)).Reverse().ToArray();
        }
        else {
            return numbers.SelectMany(n => BitConverter.GetBytes((ushort)n)).ToArray();
        }
    }

    /// <summary>
    /// Extracts a number from a byte array, assuming it's encoded as a big endian 16 bit value.
    /// </summary>
    /// <param name="data">Byte array that contains the number.</param>
    /// <param name="index">Index in the array of the first byte of the number.</param>
    /// <returns>The extracted number.</returns>
    public static ushort ExtractBigEndianUint16(this byte[] data, int index)
    {
        return (ushort)((data[index] << 8) + data[index + 1]);
    }

    /// <summary>
    /// Extracts a number from a byte array, assuming it's encoded as a big endian 24 bit value.
    /// </summary>
    /// <param name="data">Byte array that contains the number.</param>
    /// <param name="index">Index in the array of the first byte of the number.</param>
    /// <returns>The extracted number.</returns>
    public static int ExtractBigEndianUint24(this byte[] data, int index)
    {
        return (data[index] << 16) + (data[index + 1] << 8) + data[index + 2];
    }
}
