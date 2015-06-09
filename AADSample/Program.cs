using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AADSample
{
    class Program
    {
        const string ARMResource = "https://management.core.windows.net/";
        const string TokenEndpoint = "https://login.windows.net/{0}/oauth2/token";

        // client id for UPN is fixed to PowerShell SDK client id
        const string UPNPayload = "resource={0}&client_id=1950a258-227b-4e31-a9cf-717495945fc2&grant_type=password&username={1}&password={2}&scope=openid";
        const string SPNPayload = "resource={0}&client_id={1}&grant_type=client_credentials&client_secret={2}";
        const string AssertionPayload = "resource={0}&client_assertion_type={1}&client_assertion={2}&grant_type=client_credentials";

        static void Main(string[] args)
        {
            try
            {
                OAuthToken token1 = AcquireTokenBySPN(
                    tenantId: "tenantId",
                    clientId: "clientId",
                    clientSecret: "clientSecret").Result;
                Console.WriteLine(token1.access_token);

                OAuthToken token2 = AcquireTokenByUPN(
                    tenantId: "tenantId",
                    userName: "upn",
                    password: "password").Result;
                Console.WriteLine(token2.access_token);

                X509Certificate2 cert = null;
                OAuthToken token3 = AcquireTokenByX509(
                    tenantId: "tenantId",
                    clientId: "clientId",
                    cert: cert).Result;
                Console.WriteLine(token3.access_token);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static async Task<OAuthToken> AcquireTokenBySPN(string tenantId, string clientId, string clientSecret)
        {
            var payload = String.Format(SPNPayload,
                                        WebUtility.UrlEncode(ARMResource),
                                        WebUtility.UrlEncode(clientId),
                                        WebUtility.UrlEncode(clientSecret));

            return await HttpPost(tenantId, payload);
        }

        static async Task<OAuthToken> AcquireTokenByUPN(string tenantId, string userName, string password)
        {
            var payload = String.Format(UPNPayload,
                                        WebUtility.UrlEncode(ARMResource),
                                        WebUtility.UrlEncode(userName),
                                        WebUtility.UrlEncode(password));

            return await HttpPost(tenantId, payload);
        }

        static async Task<OAuthToken> AcquireTokenByX509(string tenantId, string clientId, X509Certificate2 cert)
        {
            var jwt = GetClientAssertion(tenantId, clientId, cert);
            var payload = String.Format(AssertionPayload,
                                        WebUtility.UrlEncode(ARMResource),
                                        WebUtility.UrlEncode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                                        WebUtility.UrlEncode(jwt));

            return await HttpPost(tenantId, payload);
        }

        static string GetClientAssertion(string tenantId, string clientId, X509Certificate2 cert)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim("sub", clientId));

            var handler = new JwtSecurityTokenHandler();
            var credentials = new X509SigningCredentials(cert);
            return handler.CreateToken(clientId, String.Format(TokenEndpoint, tenantId), new ClaimsIdentity(claims), null, credentials).RawData;
        }

        static async Task<OAuthToken> HttpPost(string tenantId, string payload)
        {
            using (var client = new HttpClient())
            {
                var address = String.Format(TokenEndpoint, tenantId);
                var content = new StringContent(payload, Encoding.UTF8, "application/x-www-form-urlencoded");
                using (var response = await client.PostAsync(address, content))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("Status:  {0}", response.StatusCode);
                        Console.WriteLine("Content: {0}", await response.Content.ReadAsStringAsync());
                    }

                    response.EnsureSuccessStatusCode();

                    return await response.Content.ReadAsAsync<OAuthToken>();
                }
            }
        }
    }
}
