﻿using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace JsonWebToken.Performance
{
    [Config(typeof(DefaultCoreConfig))]
    [BenchmarkCategory("CI-CD")]
    public class ValidateUnsignedTokenBenchmark : ValidateUnsignedToken
    {
        public override IEnumerable<string> GetTokens()
        {
            yield return "JWT 6 claims";
            yield return "JWT 16 claims";
        }
    }
}
