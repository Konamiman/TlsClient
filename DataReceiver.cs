using Konamiman.TlsClient.Cryptography;
using Konamiman.TlsClient.DataTransport;
using Konamiman.TlsClient.Enums;
using System;
using System.Linq;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("NestorTLSTester")]

namespace Konamiman.TlsClient;

/// <summary>
/// This class handles the reception of TLS records, taking care of all the low-level nuances:
/// 
/// - All the possible fragmentations:
///   - TLS records fragmented in several frames/packets at the data transport level.
///   - Handshake messages fragmented in several TLS records.
///   - Several handshake messages coalesced in one single TLS record.
///   - Any combination of the above (e.g. a record containing "two and half" handshake messages).
/// - Decryption of "application data" records.
/// 
/// How to use:
/// 
/// 1. Invoke the "Run" method.
/// 2. Look at the "IsComplete" property. If it's false, goto 1.
/// 3. Look at the "RecordType", "HandshakeType" and "Data" properties (also "HandshakeHeader" if needed).
/// 4. To start over (and receive the next record), just goto 1.
/// 
/// For handshake messages "Data" will always contain one single full message, regardless of
/// message fragmentation or coalescing.
/// </summary>
internal class DataReceiver
{
    private IDataTransport dataTransport;

    /// <summary>
    /// The data decryptor to use. Needs to be set as soon as the keys are negotiated.
    /// </summary>
    public RecordEncryption Encryption { get; set; } = null;

    /// <summary>
    /// Indicates that a full record has been received and thus the values of
    /// "RecordType", "HandshakeType", "Data" and "HandshakeHeader" are good.
    /// </summary>
    public bool IsComplete { get; private set; } = false;

    /// <summary>
    /// The received record data, already decrypted (if it had been received encrypted),
    /// and not including the 5 byte record header nor (if it's a handshake message)
    /// the 4 byte handshake header.
    /// </summary>
    public byte[] Data { get; private set; } = null;

    /// <summary>
    /// The received 4 byte handshake header (if a handshake message has been received).
    /// </summary>
    public byte[] HandshakeHeader { get; private set; } = null;

    /// <summary>
    /// The received record type.
    /// </summary>
    public RecordContentType RecordType { get; private set; } = RecordContentType.None;

    /// <summary>
    /// The received handshake message type (if a handshake message has been received).
    /// </summary>
    public HandshakeType HandshakeType { get; private set; } = HandshakeType.None;

    bool receivingHeader = true;

    byte[] recordData = new byte[16384];

    int totalSize = 5;

    int receivedSize = 0;

    byte[]? nextHandshakeData;

    byte[] handshakeData;

    int handshakeSize;

    int receivedHandshakeSize;

    bool receivingHandshake = false;

    public DataReceiver(IDataTransport dataTransport)
    {
        this.dataTransport = dataTransport;
    }

    public void Run()
    {
        if(IsComplete) {
            InitForNewRecord();
            IsComplete = false;
        }

        if(nextHandshakeData != null) {
            //Simulate the reception of a record whose content is the next handshake data fragment
            RecordType = RecordContentType.Handshake;
            Array.Copy(nextHandshakeData, recordData, nextHandshakeData.Length);
            totalSize = receivedSize = nextHandshakeData.Length;
            nextHandshakeData = null;
        }
        else {
            var receivedNow = dataTransport.Receive(recordData, receivedSize, totalSize - receivedSize);
            receivedSize += receivedNow;
            if(receivedSize < totalSize) {
                return;
            }
        }

        if(RecordType is RecordContentType.None) {
            // We have a full record header
            receivingHeader = false;

            RecordType = (RecordContentType)recordData[0];
            //var legacyVersion = recordData.ExtractBigEndianUint16(1);
            totalSize = recordData.ExtractBigEndianUint16(3);

            if(totalSize > 16384 + (RecordType is RecordContentType.ApplicationData ? 256 : 0)) {
                throw new ProtocolError(AlertCode.recordOverflow, $"Received a record with a declared size of {totalSize}");
            }

            receivedSize = dataTransport.Receive(recordData, 0, totalSize);
            if(receivedSize < totalSize) {
                return;
            }
        }

        // We have a full record

        if(RecordType is RecordContentType.ApplicationData) {
            (RecordType, totalSize) = Encryption.Decrypt(recordData, recordData, totalSize);
        }

        if(RecordType is not RecordContentType.Handshake) {
            if(receivingHandshake) {
                throw new ProtocolError(AlertCode.unexpectedMessage, $"Received a record of type {RecordType} in the middle of the reception of a fragmented handshake message");
            }

            Data = recordData.Take(totalSize).ToArray();
            IsComplete = true;
            return;
        }

        // We have received a handshake message fragment

        if(!receivingHandshake) {
            //It was the first fragment
            if(recordData.Length < 4) {
                throw new ProtocolError(AlertCode.decodeError, "Received a first handshake fragment smaller than 4 bytes");
            }

            receivingHandshake = true;
            HandshakeHeader = recordData.Take(4).ToArray();
            HandshakeType = (HandshakeType)recordData[0];
            handshakeSize = recordData.ExtractBigEndianUint24(1);
            handshakeData = recordData.Skip(4).Take(totalSize-4).ToArray();
            receivedHandshakeSize = handshakeData.Length;
        }
        else {
            handshakeData = [.. handshakeData, .. recordData.Take(totalSize)];
            receivedHandshakeSize += totalSize;
        }

        if(receivedHandshakeSize < handshakeSize) {
            InitForNewRecord();
            return;
        }

        // The handshake message is complete

        IsComplete = true;
        receivingHandshake = false;

        if(receivedHandshakeSize == handshakeSize) {
            Data = handshakeData.ToArray();
            nextHandshakeData = null;
            receivedHandshakeSize = 0;
            return;
        }

        // There was a fragment of the next handshake message(s) at the end of the record

        Data = handshakeData.Take(handshakeSize).ToArray();
        nextHandshakeData = handshakeData.Skip(handshakeSize).ToArray();
    }

    private void InitForNewRecord()
    {
        if(!receivingHandshake) {
            HandshakeType = HandshakeType.None;
        }
        RecordType = RecordContentType.None;
        receivedSize = 0;
        totalSize = 5;
        receivingHeader = true;
    }
}
