﻿using System;

namespace JsonWebToken
{
    /// <summary>
    /// See: http://tools.ietf.org/html/rfc7519 and http://www.rfc-editor.org/info/rfc7515
    /// </summary>
    public sealed class JsonWebTokenWriter : IDisposable
    {
        private int _defaultTokenLifetimeInMinutes = DefaultTokenLifetimeInMinutes;

        /// <summary>
        /// Default lifetime of tokens created. When creating tokens, if 'expires' and 'notbefore' are both null, then a default will be set to: expires = DateTime.UtcNow, notbefore = DateTime.UtcNow + TimeSpan.FromMinutes(TokenLifetimeInMinutes).
        /// </summary>
        public static readonly int DefaultTokenLifetimeInMinutes = 60;
        private readonly SignerFactory _signatureFactory = new SignerFactory();
        private readonly KeyWrapperFactory _keyWrapFactory = new KeyWrapperFactory();
        private readonly AuthenticatedEncryptorFactory _authenticatedEncryptionFactory = new AuthenticatedEncryptorFactory();
        private JsonHeaderCache _headerCache = new JsonHeaderCache();
        private bool _disposed;

        /// <summary>
        /// Gets or sets the token lifetime in minutes.
        /// </summary>
        /// <remarks>Used by <see cref="CreateToken(JsonWebTokenDescriptor)"/> to set the default expiration ('exp'). <see cref="DefaultTokenLifetimeInMinutes"/> for the default.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public int TokenLifetimeInMinutes
        {
            get
            {
                return _defaultTokenLifetimeInMinutes;
            }

            set
            {
                if (value < 1)
                {
                    Errors.ThrowMustBeGreaterThanZero(nameof(value), value);
                }

                _defaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets or sets a bool that controls if token creation will set default 'exp', 'nbf' and 'iat' if not specified.
        /// </summary>
        /// <remarks>See: <see cref="DefaultTokenLifetimeInMinutes"/>, <see cref="TokenLifetimeInMinutes"/> for defaults and configuration.</remarks>
        public bool SetDefaultTimesOnTokenCreation { get; set; } = false;

        public bool IgnoreTokenValidation { get; set; } = false;

        public bool EnableHeaderCaching
        {
            get => _headerCache != null;
            set
            {
                if (value )
                {
                    if ( _headerCache == null)
                    {
                        _headerCache = new JsonHeaderCache();
                    }
                }
                else
                {
                    _headerCache = null;
                }
            }
        }

        public string WriteToken(JwtDescriptor descriptor)
        {
            if (descriptor == null)
            {
                throw new ArgumentNullException(nameof(descriptor));
            }

            if (descriptor is IJwtPayloadDescriptor claimsDescriptor)
            {
                if (SetDefaultTimesOnTokenCreation && (!claimsDescriptor.ExpirationTime.HasValue || !claimsDescriptor.IssuedAt.HasValue || !claimsDescriptor.NotBefore.HasValue))
                {
                    DateTime now = DateTime.UtcNow;
                    if (!claimsDescriptor.ExpirationTime.HasValue)
                    {
                        claimsDescriptor.ExpirationTime = now + TimeSpan.FromMinutes(TokenLifetimeInMinutes);
                    }

                    if (!claimsDescriptor.IssuedAt.HasValue)
                    {
                        claimsDescriptor.IssuedAt = now;
                    }
                }
            }

            if (descriptor.Algorithm == null)
            {
                descriptor.Algorithm = SignatureAlgorithm.None.Name;
            }

            if (!IgnoreTokenValidation)
            {
                descriptor.Validate();
            }

            var encodingContext = new EncodingContext(_headerCache, _signatureFactory, _keyWrapFactory, _authenticatedEncryptionFactory);
            return descriptor.Encode(encodingContext);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _authenticatedEncryptionFactory.Dispose();
            _signatureFactory.Dispose();
            _keyWrapFactory.Dispose();
            _disposed = true;
        }
    }
}
