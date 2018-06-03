using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace JsonWebToken.Tests
{
    public class JsonWebTokenWriterTests
    {
        [Theory]
        [MemberData(nameof(GetDescriptors))]
        public void Write(JwtDescriptor descriptor)
        {
            JsonWebTokenWriter writer = new JsonWebTokenWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(Keys.Jwks);
            var result = reader.TryReadToken(value, TokenValidationParameters.NoValidation);
            var jwt = result.Token;

            var payload = descriptor as IJwtPayloadDescriptor;
            Assert.Equal(payload.IssuedAt, jwt.Payload.Iat);
            Assert.Equal(payload.ExpirationTime, jwt.ExpirationTime);
            Assert.Equal(payload.Issuer, jwt.Issuer);
            Assert.Equal(payload.Audiences.First(), jwt.Audiences.First());
            Assert.Equal(payload.JwtId, jwt.Id);
        }

        [Fact]
        public void Write_RSAES_PKCS1_v1_5_and_AES_128_CBC_HMAC_SHA_256()
        {
            var plaintext = "Live long and prosper.";
            var key = new RsaJwk
            {
                N = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
                E = "AQAB",
                D = "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
                P = "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
                Q = "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
                DP = "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
                DQ = "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
                QI = "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo",
                Alg = "RSA1_5"
            };

            var descriptor = new PlaintextJweDescriptor();
            descriptor.Payload = plaintext;
            descriptor.Key = key;
            descriptor.EncryptionAlgorithm = "A128CBC-HS256";

            JsonWebTokenWriter writer = new JsonWebTokenWriter();
            var value = writer.WriteToken(descriptor);

            var reader = new JsonWebTokenReader(key);
            var result = reader.TryReadToken(value, TokenValidationParameters.NoValidation);
            var jwt = result.Token;

            Assert.Equal(plaintext, jwt.PlainText);
        }

        public static IEnumerable<object[]> GetDescriptors()
        {
            foreach (var key in Keys.Jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Sig))
            {
                foreach (var jwt in Tokens.Descriptors)
                {
                    yield return new object[]
                    {
                        new JwsDescriptor
                        {
                            Key = key,
                            JwtId = jwt.JwtId,
                            Audiences = jwt.Audiences,
                            ExpirationTime = jwt.ExpirationTime,
                            IssuedAt = jwt.IssuedAt,
                            Issuer = jwt.Issuer,
                            NotBefore = jwt.NotBefore
                        }
                    };
                }
            }

            var encryptionAlgorithms = new[] { ContentEncryptionAlgorithms.Aes128CbcHmacSha256, ContentEncryptionAlgorithms.Aes192CbcHmacSha384, ContentEncryptionAlgorithms.Aes256CbcHmacSha512 };
            foreach (var encKey in Keys.Jwks.Keys.Where(k => k.Use == JsonWebKeyUseNames.Enc && k.Kty == JsonWebAlgorithmsKeyTypes.Octet))
            {
                foreach (var enc in encryptionAlgorithms)
                {
                    if (!encKey.IsSupportedAlgorithm(enc))
                    {
                        continue;
                    }

                    var sigKey = Keys.Jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
                    foreach (var jwt in Tokens.Descriptors)
                    {
                        yield return new object[] {
                            new JweDescriptor()
                            {
                                Key = encKey,
                                EncryptionAlgorithm = enc,
                                ContentType = "JWT",
                                Payload = new JwsDescriptor
                                {
                                    Key = sigKey,
                                    JwtId = jwt.JwtId,
                                    Audiences = jwt.Audiences,
                                    ExpirationTime = jwt.ExpirationTime,
                                    IssuedAt = jwt.IssuedAt,
                                    Issuer = jwt.Issuer,
                                    NotBefore = jwt.NotBefore
                                }
                            }
                        };
                    }
                }
            }
        }
    }
}