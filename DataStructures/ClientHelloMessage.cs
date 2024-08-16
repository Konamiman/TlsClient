using Konamiman.TlsClient.Enums;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Konamiman.TlsClient.DataStructures
{
    /// <summary>
    /// Represents a ClientHello message.
    /// After creating an instance, set its public properties as appropriate
    /// and then invoke "ToByteArray".
    /// </summary>
    internal class ClientHelloMessage
    {
        public ClientHelloMessage()
        {
            Random = new byte[32];
            RandomNumberGenerator.Create().GetBytes(Random);
        }

        public byte[] Random { get; set; }

        public CipherSuite[] CipherSuites { get; set; } = null;

        public byte[] PublicKey { get; set; } = null;

        public string ServerName { get; set; } = null;

        /// <summary>
        /// Serializes the message as a TLS record, not including
        /// the 5 byte record headernor the 4 byte handshake header.
        /// </summary>
        /// <returns></returns>
        public byte[] ToByteArray()
        {
            if(Random is null) {
                throw new InvalidOperationException($"{Random} can't be null");
            }

            if(CipherSuites is null) {
                throw new InvalidOperationException($"{CipherSuites} can't be null");
            }

            if(PublicKey is null) {
                throw new InvalidOperationException($"{PublicKey} can't be null");
            }

            var extensions = GetExtensions();

            byte[] data = [
                3, 3, //legacy_version
                ..Random,
                32,
                ..RandomNumberGenerator.GetBytes(32),
                ..(CipherSuites.Length * 2).ToBigEndianUint16Bytes(),
                ..CipherSuites.Cast<ushort>()
                .ToBigEndianUint16BytesArray(),
                1, 0, //legacy_compression_methods
                ..extensions.Length.ToBigEndianUint16Bytes(),
                ..extensions
            ];

            return data;
        }

        private byte[] GetExtensions()
        {
            byte[] data = [

                // supported_versions

                ..((ushort)HandshakeExtensionType.SupportedVersions).ToBigEndianUint16Bytes(),
                0, 3, // Extension size
                2,    // Data size
                3, 4, // TLS 1.3

                //max_fragment_length

                ..((ushort)HandshakeExtensionType.MaxFragmentLength).ToBigEndianUint16Bytes(),
                0, 1, // Extension size
                1,    // 512 bytes

                //supported_groups

                ..((ushort)HandshakeExtensionType.SupportedGroups).ToBigEndianUint16Bytes(),
                0, 4, // Extension size
                0, 2, // Data size
                ..((ushort)SupportedGroup.X25519).ToBigEndianUint16Bytes(),

                //key_share

                ..((ushort)HandshakeExtensionType.KeyShare).ToBigEndianUint16Bytes(),
                0, 38, // Extension size
                0, 36, // Data size
                ..((ushort)SupportedGroup.X25519).ToBigEndianUint16Bytes(),
                0, 32, // Key size
                ..PublicKey,

                //signature_algorithms

                ..((ushort)HandshakeExtensionType.SignatureAlgorithms).ToBigEndianUint16Bytes(),
                0, 14, // Extension size
                0, 12, // Data size
                4, 1,  // RSA-PKCS1-SHA256
                5, 1,  // RSA-PKCS1-SHA384
                8, 4,  // RSA-PSS-RSAE-SHA256
                8, 5,  // RSA-PSS-RSAE-SHA384
                4, 3,  // ECDSA-SECP256r1-SHA256
                5, 3,  // ECDSA-SECP384r1-SHA384
            ];

            if(!String.IsNullOrWhiteSpace(ServerName)) {
                var serverNameBytes = Encoding.ASCII.GetBytes(ServerName.Trim());
                var serverNameLength = serverNameBytes.Length;

                data = data.Concat<byte>([
                    ..((ushort)HandshakeExtensionType.ServerName).ToBigEndianUint16Bytes(),
                    ..(serverNameLength+5).ToBigEndianUint16Bytes(), // Extension size
                    ..(serverNameLength+3).ToBigEndianUint16Bytes(), // Data size
                    0, //Name type: "DNS hostname"
                    ..serverNameLength.ToBigEndianUint16Bytes(),     // Name size
                    ..serverNameBytes
                ]).ToArray();
            }

            return data;
        }
    }
}
