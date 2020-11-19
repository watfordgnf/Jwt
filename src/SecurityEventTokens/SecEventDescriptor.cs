﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

namespace JsonWebToken
{
    /// <summary>Defines a signed Security Event Token. <seealso cref="EncryptedSecEventDescriptor"/> for encrypted Security Event Token.</summary>
    public class SecEventDescriptor : JwsDescriptor
    {
        public SecEventDescriptor(Jwk signingKey, SignatureAlgorithm alg, string? typ = SecEventsMediaTypes.SecEvent, string? cty = null)
            : base(signingKey, alg, typ, cty)
        {
        }

        public override void Validate()
        {
            base.Validate();
            CheckRequiredClaimAsString(Claims.Iss);
            CheckRequiredClaimAsInteger(Claims.Iat);
            CheckRequiredClaimAsString(Claims.Jti);
            if (TryGetClaim(SecEventClaims.Events, out var events))
            {
                if (events.Type == JwtValueKind.Object)
                {
                    JsonObject evts = (JsonObject)events.Value;
                    foreach (JwtMember evt in evts)
                    {
                        if (evt.Value is SecEvent evcts)
                        {
                            evcts.Validate();
                        }
                    }
                }
                else
                {
                    ThrowHelper.ThrowJwtDescriptorException_ClaimMustBeOfType(SecEventClaims.Events, JwtValueKind.Object);
                }
            }
            else
            {
                ThrowHelper.ThrowJwtDescriptorException_ClaimIsRequired(SecEventClaims.Events);
            }
        }
    }
}
