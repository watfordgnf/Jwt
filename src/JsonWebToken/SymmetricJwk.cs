﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System;
using System.Buffers;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using JsonWebToken.Internal;

namespace JsonWebToken
{
    /// <summary>
    /// Represents a symmetric JSON Web Key as defined in https://tools.ietf.org/html/rfc7518#section-6.
    /// </summary>
    public sealed class SymmetricJwk : Jwk
    {
#if !SUPPORT_SPAN_CRYPTO
        private static readonly RandomNumberGenerator _randomNumberGenerator = RandomNumberGenerator.Create();
#endif
        internal static new readonly SymmetricJwk Empty = new SymmetricJwk(Array.Empty<byte>());

        private readonly byte[] _k;

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The binary key material.</param>
        private SymmetricJwk(ReadOnlySpan<byte> k)
        {
            _k = k.ToArray();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The binary key material.</param>
        private SymmetricJwk(byte[] k)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = k;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The key material encoded in Base64-URL.</param>
        private SymmetricJwk(string k)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = Base64Url.Decode(k);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
#nullable disable
        internal SymmetricJwk(JwtObject @object)
#nullable enable
        {
            for (int i = 0; i < @object.Count; i++)
            {
                var property = @object[i];
                var name = property.Utf8Name;
                switch (property.Type)
                {
                    case JwtTokenType.Array:
                        Populate(name, (JwtArray)property.Value!);
                        break;
                    case JwtTokenType.String:
                        if (name.SequenceEqual(JwkParameterNames.KUtf8))
                        {
                            _k = Base64Url.Decode((string)property.Value!);
                        }
                        else
                        {
                            Populate(name, (string)property.Value!);
                        }
                        break;
                    case JwtTokenType.Utf8String:
                        Populate(name, (byte[])property.Value!);
                        break;
                    default:
                        break;
                }
            }

            if (_k is null)
            {
                ThrowHelper.ThrowFormatException_MalformedJson("Missing 'k' property.");
            }
        }

        internal SymmetricJwk(ref Utf8JsonReader reader)
        {
            byte[]? k = null;
            while (reader.Read() && reader.TokenType is JsonTokenType.PropertyName)
            {
                var propertyName = reader.ValueSpan;
                ref byte propertyNameRef = ref MemoryMarshal.GetReference(propertyName);
                reader.Read();
                switch (reader.TokenType)
                {
                    case JsonTokenType.String:
                        switch (propertyName.Length)
                        {
                            case 1 when propertyNameRef == (byte)'k':
                                k = Base64Url.Decode(reader.ValueSpan);
                                break;

                            case 3:
                                PopulateThree(ref reader, ref propertyNameRef, this);
                                break;
                            case 8:
                                PopulateEight(ref reader, ref propertyNameRef, this);
                                break;
                            default:
                                break;
                        }
                        break;
                    case JsonTokenType.StartObject:
                        PopulateObject(ref reader);
                        break;
                    case JsonTokenType.StartArray:
                        PopulateArray(ref reader, ref propertyNameRef, propertyName.Length, this);
                        break;
                    default:
                        break;
                }
            }

            if (!(reader.TokenType is JsonTokenType.EndObject))
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            if (k is null)
            {
                ThrowHelper.ThrowArgumentException_MalformedKey();
            }

            _k = k;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The binary key material.</param>
        /// <param name="alg">The <see cref="SignatureAlgorithm"/>.</param>
        private SymmetricJwk(byte[] k, SignatureAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = k;
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The binary key material.</param>
        /// <param name="alg">The <see cref="SignatureAlgorithm"/>.</param>
        private SymmetricJwk(ReadOnlySpan<byte> k, SignatureAlgorithm alg)
            : base(alg)
        {
            _k = k.ToArray();
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The key material encoded in Base64-URL.</param>
        /// <param name="alg">The <see cref="SignatureAlgorithm"/>.</param>
        private SymmetricJwk(string k, SignatureAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = Base64Url.Decode(k);
            if (!SupportSignature(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The binary key material.</param>
        /// <param name="alg">The <see cref="SignatureAlgorithm"/>.</param>
        private SymmetricJwk(byte[] k, KeyManagementAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = k;
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The binary key material.</param>
        /// <param name="alg">The <see cref="SignatureAlgorithm"/>.</param>
        private SymmetricJwk(ReadOnlySpan<byte> k, KeyManagementAlgorithm alg)
            : base(alg)
        {
            _k = k.ToArray();
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k">The key material encoded in Base64-URL.</param>
        /// <param name="alg">The <see cref="KeyManagementAlgorithm"/>.</param>
        private SymmetricJwk(string k, KeyManagementAlgorithm alg)
            : base(alg)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            _k = Base64Url.Decode(k);
            if (!SupportKeyManagement(alg))
            {
                ThrowHelper.ThrowNotSupportedException_Algorithm(alg);
            }
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> Kty => JwkTypeNames.Octet;

        /// <summary>
        /// Gets or sets the 'k' (Key Value).
        /// </summary>
        public ReadOnlySpan<byte> K => _k;

        /// <inheritsdoc />
        public override int KeySizeInBits => _k.Length << 3;

        internal byte[] ToArray()
            => _k;

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        /// <param name="computeThumbprint"></param>
        public static SymmetricJwk FromByteArray(byte[] bytes, bool computeThumbprint = true)
        {
            if (bytes is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.bytes);
            }

            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        /// <param name="algorithm">The <see cref="SignatureAlgorithm"/>.</param>
        /// <param name="computeThumbprint"></param>
        public static SymmetricJwk FromByteArray(byte[] bytes, SignatureAlgorithm algorithm, bool computeThumbprint = true)
        {
            if (bytes is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.bytes);
            }

            var key = new SymmetricJwk(bytes, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes">An array of <see cref="byte"/> that contains the key in binary.</param>
        /// <param name="algorithm">The <see cref="KeyManagementAlgorithm"/>.</param>
        /// <param name="computeThumbprint"></param>
        public static SymmetricJwk FromByteArray(byte[] bytes, KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
        {
            if (bytes is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.bytes);
            }

            var key = new SymmetricJwk(bytes, algorithm);
            if (computeThumbprint)
            {
                ComputeKid(key);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static SymmetricJwk FromSpan(ReadOnlySpan<byte> bytes, bool computeThumbprint = true)
        {
            var key = new SymmetricJwk(bytes);
            if (computeThumbprint)
            {
                Span<byte> thumbprint = stackalloc byte[43];
                key.ComputeThumbprint(thumbprint);
                key.Kid = Utf8.GetString(thumbprint);
            }

            return key;
        }

        /// <inheritsdoc />
        public override bool SupportKeyManagement(KeyManagementAlgorithm algorithm)
        {
            return ((algorithm.Category & AlgorithmCategory.Aes) != 0 && algorithm.RequiredKeySizeInBits == KeySizeInBits) || (algorithm == KeyManagementAlgorithm.Direct);
        }

        /// <inheritsdoc />
        public override bool SupportSignature(SignatureAlgorithm algorithm)
        {
            return algorithm.Category == AlgorithmCategory.Hmac;
        }

        /// <inheritsdoc />
        public override bool SupportEncryption(EncryptionAlgorithm algorithm)
        {
            return (algorithm.Category & EncryptionType.Aes) != 0 && KeySizeInBits >= algorithm.RequiredKeySizeInBits;
        }

        /// <inheritdoc />
        protected override Signer CreateSigner(SignatureAlgorithm algorithm)
        {
            return new SymmetricSigner(this, algorithm);
        }

        /// <inheritsdoc />
        protected override KeyWrapper CreateKeyWrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            KeyWrapper value = algorithm.Category switch
            {
                AlgorithmCategory.Aes => new AesKeyWrapper(this, encryptionAlgorithm, algorithm),
#if SUPPORT_AESGCM
                AlgorithmCategory.AesGcm => new AesGcmKeyWrapper(this, encryptionAlgorithm, algorithm),
#endif
                AlgorithmCategory.Direct => new DirectKeyWrapper(this, encryptionAlgorithm, algorithm),
                _ => throw ThrowHelper.CreateNotSupportedException_AlgorithmForKeyWrap(algorithm)
            };
            return value;
        }

        /// <inheritsdoc />
        protected override KeyUnwrapper CreateKeyUnwrapper(EncryptionAlgorithm encryptionAlgorithm, KeyManagementAlgorithm algorithm)
        {
            KeyUnwrapper value = algorithm.Category switch
            {
                AlgorithmCategory.Aes => new AesKeyUnwrapper(this, encryptionAlgorithm, algorithm),
#if SUPPORT_AESGCM
                AlgorithmCategory.AesGcm => new AesGcmKeyUnwrapper(this, encryptionAlgorithm, algorithm),
#endif
                AlgorithmCategory.Direct => new DirectKeyUnwrapper(this, encryptionAlgorithm, algorithm),
                _ => throw ThrowHelper.CreateNotSupportedException_AlgorithmForKeyWrap(algorithm)
            };
            return value;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static SymmetricJwk FromBase64Url(string k, bool computeThumbprint = true)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            var key = new SymmetricJwk(k);
            if (computeThumbprint)
            {
                Span<byte> thumbprint = stackalloc byte[43];
                key.ComputeThumbprint(thumbprint);
                key.Kid = Utf8.GetString(thumbprint);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k"></param>
        /// <param name="alg"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static SymmetricJwk FromBase64Url(string k, SignatureAlgorithm alg, bool computeThumbprint = true)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            var key = new SymmetricJwk(k, alg);
            if (computeThumbprint)
            {
                Span<byte> thumbprint = stackalloc byte[43];
                key.ComputeThumbprint(thumbprint);
                key.Kid = Utf8.GetString(thumbprint);
            }

            return key;
        }

        /// <summary>
        /// Returns a new instance of <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="k"></param>
        /// <param name="alg"></param>
        /// <param name="computeThumbprint"></param>
        /// <returns></returns>
        public static SymmetricJwk FromBase64Url(string k, KeyManagementAlgorithm alg, bool computeThumbprint = true)
        {
            if (k is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.k);
            }

            var key = new SymmetricJwk(k, alg);
            if (computeThumbprint)
            {
                Span<byte> thumbprint = stackalloc byte[43];
                key.ComputeThumbprint(thumbprint);
                key.Kid = Utf8.GetString(thumbprint);
            }

            return key;
        }

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <param name="computeThumbprint">Indicates if the 'kid' should be generated.</param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(int sizeInBits, bool computeThumbprint = true)
            => FromByteArray(GenerateKeyBytes(sizeInBits), computeThumbprint);

        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint">Indicates if the 'kid' should be generated.</param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(SignatureAlgorithm algorithm, bool computeThumbprint = true)
            => FromByteArray(GenerateKeyBytes(algorithm.RequiredKeySizeInBits * 8), algorithm, computeThumbprint: computeThumbprint);
        
        /// <summary>
        /// Generates a new <see cref="SymmetricJwk"/>.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <param name="computeThumbprint">Indicates if the 'kid' should be generated.</param>
        /// <returns></returns>
        public static SymmetricJwk GenerateKey(KeyManagementAlgorithm algorithm, bool computeThumbprint = true)
            => FromByteArray(GenerateKeyBytes(algorithm.RequiredKeySizeInBits * 8), algorithm, computeThumbprint: computeThumbprint);

        private static byte[] GenerateKeyBytes(int sizeInBits)
        {
            byte[] key = new byte[sizeInBits >> 3];
#if SUPPORT_SPAN_CRYPTO
            RandomNumberGenerator.Fill(key);
#else
            _randomNumberGenerator.GetBytes(key);
#endif
            return key;
        }

        /// <inheritdoc />      
        protected override void Canonicalize(IBufferWriter<byte> bufferWriter)
        {
            using var writer = new Utf8JsonWriter(bufferWriter, Constants.NoJsonValidation);
            writer.WriteStartObject();
            int requiredBufferSize = Base64Url.GetArraySizeRequiredToEncode(_k.Length);
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = requiredBufferSize > Constants.MaxStackallocBytes
                                    ? stackalloc byte[requiredBufferSize]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(requiredBufferSize));
                int bytesWritten = Base64Url.Encode(_k, buffer);
                writer.WriteString(JwkParameterNames.KUtf8, buffer.Slice(0, bytesWritten));
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }

            writer.WriteString(JwkParameterNames.KtyUtf8, Kty);
            writer.WriteEndObject();
            writer.Flush();
        }

        /// <inheritsdoc />
        public override ReadOnlySpan<byte> AsSpan()
        {
            return _k;
        }

        /// <inheritdoc />      
        public override void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            base.WriteTo(writer);
            int requiredBufferSize = Base64Url.GetArraySizeRequiredToEncode(_k.Length);
            byte[]? arrayToReturn = null;
            try
            {
                Span<byte> buffer = requiredBufferSize > Constants.MaxStackallocBytes
                                    ? stackalloc byte[requiredBufferSize]
                                    : (arrayToReturn = ArrayPool<byte>.Shared.Rent(requiredBufferSize));
                WriteBase64UrlProperty(writer, buffer, _k, JwkParameterNames.KUtf8);
            }
            finally
            {
                if (arrayToReturn != null)
                {
                    ArrayPool<byte>.Shared.Return(arrayToReturn);
                }
            }

            writer.WriteEndObject();
        }

        /// <inheritsdoc />
        public override bool Equals(Jwk? other)
        {
            if (!(other is SymmetricJwk key))
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return _k.AsSpan().SequenceEqual(key._k);
        }

        /// <inheritsdoc />
        public override int GetHashCode()
        {
            unchecked
            {
                var k = _k;
                if (k.Length >= sizeof(int))
                {
                    return Unsafe.ReadUnaligned<int>(ref k[0]);
                }
                else
                {
                    int hash = (int)2166136261;
                    for (int i = 0; i < k.Length; i++)
                    {
                        hash = (hash ^ k[i]) * 16777619;
                    }

                    return hash;
                }
            }
        }

        /// <inheritsdoc />
        public override void Dispose()
        {
            base.Dispose();
            if (_k != null)
            {
                CryptographicOperations.ZeroMemory(_k);
            }
        }
    }
}