using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JsonWebToken.Cryptography
{
    internal static partial class Oids
    {
        // Asymmetric encryption algorithms
        internal const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
        internal const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
        internal const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
        
        internal const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
        internal const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
        internal const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";
    }
}
