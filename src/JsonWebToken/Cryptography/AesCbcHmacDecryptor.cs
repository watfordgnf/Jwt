﻿// Copyright (c) 2018 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Buffers.Binary;

namespace JsonWebToken.Internal
{
    /// <summary>
    /// Provides authenticated encryption and decryption for AES CBC HMAC algorithm.
    /// </summary>
    public sealed class AesCbcHmacDecryptor : AuthenticatedDecryptor
    {
        private readonly AesDecryptor _decryptor;
        private readonly SymmetricJwk _hmacKey;
        private readonly SymmetricSigner _signer;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCbcHmacDecryptor"/> class.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="encryptionAlgorithm"></param>
        public AesCbcHmacDecryptor(SymmetricJwk key, EncryptionAlgorithm encryptionAlgorithm)
        {
            if (key is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.key);
            }

            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            if (key.KeySizeInBits < encryptionAlgorithm.RequiredKeySizeInBits)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(key, encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBits, key.KeySizeInBits);
            }

            int keyLength = encryptionAlgorithm.RequiredKeySizeInBits >> 4;

            var keyBytes = key.K;
            var aesKey = keyBytes.Slice(keyLength).ToArray();
            _hmacKey = SymmetricJwk.FromSpan(keyBytes.Slice(0, keyLength), false);

            _decryptor = new AesCbcDecryptor(aesKey, encryptionAlgorithm);
            if (!_hmacKey.TryGetSigner(encryptionAlgorithm.SignatureAlgorithm, out var signer))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }

            _signer = (SymmetricSigner)signer;
        }

        /// <summary>
        /// Initializs a new instance of the <see cref="AesCbcHmacDecryptor"/> class.
        /// </summary>
        /// <param name="hmacKey"></param>
        /// <param name="encryptionAlgorithm"></param>
        /// <param name="decryptor"></param>
        public AesCbcHmacDecryptor(ReadOnlySpan<byte> hmacKey, EncryptionAlgorithm encryptionAlgorithm, AesDecryptor decryptor)
        {
            if (encryptionAlgorithm is null)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.encryptionAlgorithm);
            }

            if (encryptionAlgorithm.Category != EncryptionType.AesHmac)
            {
                ThrowHelper.ThrowNotSupportedException_EncryptionAlgorithm(encryptionAlgorithm);
            }

            int keyLength = encryptionAlgorithm.RequiredKeySizeInBits >> 4;
            if (hmacKey.Length < keyLength)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException_EncryptionKeyTooSmall(encryptionAlgorithm, encryptionAlgorithm.RequiredKeySizeInBits, hmacKey.Length >> 3);
            }

            _decryptor = decryptor;
            _hmacKey = SymmetricJwk.FromSpan(hmacKey.Slice(0, keyLength), false);
            if (!_hmacKey.TryGetSigner(encryptionAlgorithm.SignatureAlgorithm, out var signer))
            {
                ThrowHelper.ThrowNotSupportedException_SignatureAlgorithm(encryptionAlgorithm.SignatureAlgorithm);
            }

            _signer = (SymmetricSigner)signer;
        }

        /// <inheritdoc />
        public override bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticationTag, Span<byte> plaintext, out int bytesWritten)
        {
            if (ciphertext.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.ciphertext);
            }

            if (associatedData.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.associatedData);
            }

            if (nonce.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.nonce);
            }

            if (authenticationTag.IsEmpty)
            {
                ThrowHelper.ThrowArgumentNullException(ExceptionArgument.authenticationTag);
            }

            if (_disposed)
            {
                ThrowHelper.ThrowObjectDisposedException(GetType());
            }

            if (VerifyAuthenticationTag(nonce, associatedData, ciphertext, authenticationTag))
            {
                return _decryptor.TryDecrypt(ciphertext, nonce, plaintext, out bytesWritten);
            }
            else
            {
                plaintext.Clear();
                return ThrowHelper.TryWriteError(out bytesWritten);
            }
        }

        private bool VerifyAuthenticationTag(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag)
        {
            byte[]? byteArrayToReturnToPool = null;
            int macLength = associatedData.Length + iv.Length + ciphertext.Length + sizeof(long);
            Span<byte> macBytes = macLength <= Constants.MaxStackallocBytes
                                    ? stackalloc byte[macLength]
                                    : (byteArrayToReturnToPool = ArrayPool<byte>.Shared.Rent(macLength)).AsSpan(0, macLength);
            try
            {
                associatedData.CopyTo(macBytes);
                var bytes = macBytes.Slice(associatedData.Length);
                iv.CopyTo(bytes);
                bytes = bytes.Slice(iv.Length);
                ciphertext.CopyTo(bytes);
                bytes = bytes.Slice(ciphertext.Length);
                BinaryPrimitives.WriteInt64BigEndian(bytes, associatedData.Length << 3);
                if (!_signer.Verify(macBytes, authenticationTag))
                {
                    return false;
                }
            }
            finally
            {
                if (byteArrayToReturnToPool != null)
                {
                    ArrayPool<byte>.Shared.Return(byteArrayToReturnToPool);
                }
            }

            return true;
        }

        /// <inheritdoc />
        public override void Dispose()
        {
            if (!_disposed)
            {
                _hmacKey.Dispose();
                _decryptor.Dispose();
                _disposed = true;
            }
        }
    }
}