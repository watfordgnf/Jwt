﻿// Copyright (c) 2020 Yann Crumeyrolle. All rights reserved.
// Licensed under the MIT license. See LICENSE in the project root for license information.

using System.Text.Json;

namespace JsonWebToken
{
    public class IdentifierRecycledSecEvent : SecEvent
    {
        private static readonly JsonEncodedText _name = JsonEncodedText.Encode("https://schemas.openid.net/secevent/risc/event-type/identifier-recycled", Constants.JsonEncoder);
        public override JsonEncodedText Name => _name;
    }
}
