﻿using System;

namespace AADSample
{
    public class OAuthToken
    {
        public string token_type { get; set; }
        public string expires_in { get; set; }
        public string expires_on { get; set; }
        public string resource { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string scope { get; set; }
        public string id_token { get; set; }
    }
}
