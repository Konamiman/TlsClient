using Konamiman.TlsClient.Enums;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace Konamiman.TlsClient.Cryptography;

/// <summary>
/// This class handles AES encryption and decryption of application data,
/// handling the required sequence number/nonce increases.
/// </summary>
internal class RecordEncryption
{
    byte[] serverSequenceNumber;
    byte[] clientSequenceNumber;
    byte[] clientNonce;
    byte[] serverNonce;
    byte[] clientKey;
    byte[] serverKey;
    byte[] clientIv;
    byte[] serverIv;
    readonly int ivSize;
    readonly int tagSize;
    AesGcm encryptor;
    AesGcm decryptor;

    public RecordEncryption(TrafficKeys keys, int tagSize)
    {
        this.ivSize = keys.ClientIv.Length;
        this.tagSize = tagSize;

        keys.KeysGenerated += OnKeysGenerated;
        OnKeysGenerated(keys, true);
        OnKeysGenerated(keys, false);
    }

    public byte[] Encrypt(RecordContentType contentType, byte[] content, int index = 0, int size = -1, int paddingLength = 0)
    {
        if(size == -1) {
            size = content.Length;
        }

        var contentToEncrypt = content
            .Skip(index).Take(size)
            .Concat([(byte)contentType])
            .Concat(Enumerable.Repeat<byte>(0, paddingLength))
            .ToArray();

        var encryptedLength = contentToEncrypt.Length + tagSize;
        byte[] additionalData = [
            (byte)RecordContentType.ApplicationData,
            3, 3,
            ..encryptedLength.ToBigEndianUint16Bytes()
        ];
        var encryptedContent = new byte[contentToEncrypt.Length];
        var tag = new byte[tagSize];

        try {
            encryptor.Encrypt(clientNonce, contentToEncrypt, encryptedContent, tag, additionalData);
        }
        catch(Exception ex) {
            throw new ProtocolError(AlertCode.internalError, $"Error when encrypting data: ({ex.GetType().Name}) {ex.Message}");
        }

        IncreaseSequenceNumber(clientSequenceNumber, clientNonce, clientIv);
        return encryptedContent.Concat(tag).ToArray();
    }

    public (RecordContentType, int) Decrypt(byte[] encryptedContent, byte[] destination, int? encryptedLength = null)
    {
        encryptedLength ??= encryptedContent.Length;
        byte[] additionalData = [
            (byte)RecordContentType.ApplicationData,
            3,3,
            ..encryptedLength.Value.ToBigEndianUint16Bytes()
        ];
        var innerDataLength = encryptedLength.Value - tagSize;
        var tag = encryptedContent.Skip(innerDataLength).Take(tagSize).ToArray();
        var cipherText = encryptedContent.Take(innerDataLength).ToArray();
        var decryptedContent = new byte[innerDataLength];

        try {
            decryptor.Decrypt(serverNonce, cipherText, tag, decryptedContent, additionalData);
        }
        catch(Exception ex) {
            throw new ProtocolError(AlertCode.badRecordMac, $"Error when decrypting data: ({ex.GetType().Name}) {ex.Message}");
        }

        decryptedContent = decryptedContent.Reverse().SkipWhile(c => c == 0).Reverse().ToArray();
        if(decryptedContent.Length == 0) {
            throw new ProtocolError(AlertCode.decodeError, "Received an encrypted message whose plaintext payload was all zeros");
        }

        var contentType = decryptedContent[^1];
        decryptedContent = decryptedContent.Take(decryptedContent.Length - 1).ToArray();
        Array.Copy(decryptedContent, destination, decryptedContent.Length);

        IncreaseSequenceNumber(serverSequenceNumber, serverNonce, serverIv);
        return ((RecordContentType)contentType, decryptedContent.Length);
    }

    private void IncreaseSequenceNumber(byte[] sequenceNumber, byte[] nonce, byte[] iv, int index = 0)
    {
        var sequenceIndex = ivSize - 1 - index;
        sequenceNumber[sequenceIndex]++;
        if(sequenceNumber[sequenceIndex] == 0) {
            IncreaseSequenceNumber(sequenceNumber, nonce, iv, index + 1);
        }

        nonce[sequenceIndex] = (byte)(sequenceNumber[sequenceIndex] ^ iv[sequenceIndex]);
    }

    private void OnKeysGenerated(object? sender, bool forServer)
    {
        var keys = sender as TrafficKeys;
        if(forServer) {
            serverKey = keys.ServerKey;
            serverIv = keys.ServerIv;
            serverSequenceNumber = Enumerable.Repeat<byte>(0, ivSize).ToArray();
            serverNonce = keys.ServerIv.ToArray();
            decryptor = new AesGcm(serverKey, tagSize);
        }
        else {
            clientKey = keys.ClientKey;
            clientIv = keys.ClientIv;
            clientSequenceNumber = Enumerable.Repeat<byte>(0, ivSize).ToArray();
            clientNonce = keys.ClientIv.ToArray();
            encryptor = new AesGcm(clientKey, tagSize);
        }
    }
}

