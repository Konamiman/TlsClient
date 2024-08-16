using Konamiman.TlsClient.Enums;
using System;
using System.Linq;

namespace Konamiman.TlsClient.DataStructures
{
    /// <summary>
    /// Represents a received ServerHello message.
    /// Create an instance from the received record data with "Parse",
    /// then read its public properties.
    /// </summary>
    internal class ServerHelloMessage
    {
        public byte[] Random { get; private set; }

        public CipherSuite CipherSuite { get; private set; }

        public bool IsTls13 { get; private set; }

        public bool IsHelloRetryRequest { get; private set; }

        public byte[] PublicKey { get; private set; } = null;

        public byte[] Cookie { get; private set; } = null;

        private static readonly byte[] HelloRetryRequestRandom = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };

        /// <summary>
        /// Create a new instance of the class from the record data.
        /// </summary>
        /// <param name="data">Record data, not including the 5 byte record header nor the 4 byte handshake header.</param>
        /// <param name="index"></param>
        /// <param name="dataLength"></param>
        /// <returns></returns>
        public static ServerHelloMessage Parse(byte[] data)
        {
            return new ServerHelloMessage(data);
        }

        private ServerHelloMessage(byte[] data)
        {
            var index = 0;
            var remainingLength = data.Length;

            VerifyDataLength(remainingLength, 2 + 32 + 1); //legacy_version, random, len(legacy_session_id_echo)

            var legacyVersion = data.ExtractBigEndianUint16(index);
            if(legacyVersion != 0x0303) {
                throw new Exception($"legacy_version is 0x{legacyVersion:X4}, expected 0x0303");
            }

            Random = data.Skip(index + 2).Take(32).ToArray();
            IsHelloRetryRequest = Random.SequenceEqual(HelloRetryRequestRandom);

            index += 2 + 32;             //Now index points to len(legacy_session_id_echo)
            remainingLength -= (2 + 32);

            var legacySessionIdLength = data[index];
            index++;
            remainingLength--;
            VerifyDataLength(remainingLength, legacySessionIdLength);
            index += legacySessionIdLength; //Now index points past legacy_session_id_echo
            remainingLength -= legacySessionIdLength;
            //TODO: Check if legacySessionId matches the value that was sent in CloientHello.

            CipherSuite = (CipherSuite)data.ExtractBigEndianUint16(index);
            index += 2; //Now index points to legacy_compression_method
            remainingLength -= 2;

            VerifyDataLength(remainingLength, 1 + 2); //legacy_compression_method, len(extensions)
            //var legacyCompressionMethod = data[index];
            index++; //Now index points to len(extensions)
            remainingLength--;

            VerifyDataLength(remainingLength, 2); //len(extensions)
            var extensionsLength = data.ExtractBigEndianUint16(index);
            index += 2;
            remainingLength -= 2;
            VerifyDataLength(remainingLength, extensionsLength);

            ProcessExtensions(data, index, extensionsLength);

            if(PublicKey is null) {
                throw new ProtocolError(AlertCode.handshakeFailure, "The server didn't provide a puplic key in the ServerHello message");
            }
        }

        private void ProcessExtensions(byte[] data, int index, int dataLength)
        {
            while(dataLength > 0) {
                VerifyDataLength(dataLength, 2 + 2); // extension_type, len(extension_data);
                
                var extensionType = (HandshakeExtensionType)data.ExtractBigEndianUint16(index); 
                var extensionLength = data.ExtractBigEndianUint16(index + 2);
                index += 4;
                dataLength -= 4;
                VerifyDataLength(dataLength, extensionLength);

                switch(extensionType) {
                    case HandshakeExtensionType.SupportedVersions:
                        VerifyDataLength(dataLength, 2); // selected_version
                        var selectedVersion = data.ExtractBigEndianUint16(index);
                        IsTls13 = selectedVersion == 0x0304;
                        index += 2;
                        dataLength -= 2;
                        break;
                    case HandshakeExtensionType.KeyShare:
                        VerifyDataLength(dataLength, 2 + 2); // group, len(key_exchange)
                        var groupId = (SupportedGroup)data.ExtractBigEndianUint16(index);
                        var keyLength = data.ExtractBigEndianUint16(index + 2);
                        index += 4;
                        dataLength -= 4;
                        VerifyDataLength(dataLength, keyLength);

                        if(groupId == SupportedGroup.X25519) {
                            PublicKey = data.Skip(index).Take(keyLength).ToArray();
                        }

                        index += keyLength;
                        dataLength -= keyLength;
                        break;
                    case HandshakeExtensionType.Cookie:
                        VerifyDataLength(dataLength, 2); // len(cookie)
                        var cookieLength = data.ExtractBigEndianUint16(index);
                        index += 2;
                        dataLength += 2;
                        VerifyDataLength(dataLength, cookieLength);
                        Cookie = data.Skip(index).Take(cookieLength).ToArray();
                        index += cookieLength;
                        dataLength -= cookieLength;
                        break;
                    default:
                        index += extensionLength;
                        dataLength -= extensionLength;
                        break;
                }
            }
        }

        private void VerifyDataLength(int remainingLength, int minimum)
        {
            if(remainingLength < minimum) {
                throw new IndexOutOfRangeException("Unexpected end of record found");
            }
        }
    }
}
