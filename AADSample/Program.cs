using System;
using System.Net;
using System.Net.Http;
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

        static void Main(string[] args)
        {
            try
            {
                AcquireTokenBySPN(tenantId: "tenantId",
                                  clientId: "clientId",
                                  clientSecret: "clientSecret").Wait();

                AcquireTokenByUPN(tenantId: "tenantId",
                                  userName: "upn",
                                  password: "password").Wait();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static async Task AcquireTokenBySPN(string tenantId, string clientId, string clientSecret)
        {
            var payload = String.Format(SPNPayload,
                                        WebUtility.UrlEncode(ARMResource),
                                        WebUtility.UrlEncode(clientId),
                                        WebUtility.UrlEncode(clientSecret));

            await HttpPost(tenantId, payload);
        }

        static async Task AcquireTokenByUPN(string tenantId, string userName, string password)
        {
            var payload = String.Format(UPNPayload,
                                        WebUtility.UrlEncode(ARMResource),
                                        WebUtility.UrlEncode(userName),
                                        WebUtility.UrlEncode(password));

            await HttpPost(tenantId, payload);
        }

        static async Task HttpPost(string tenantId, string payload)
        {
            using (var client = new HttpClient())
            {
                var address = String.Format(TokenEndpoint, tenantId);
                var content = new StringContent(payload, Encoding.UTF8, "application/x-www-form-urlencoded");
                using (var response = await client.PostAsync(address, content))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("Status: {0}", response.StatusCode);
                    }
                    Console.WriteLine(await response.Content.ReadAsStringAsync());
                }
            }
        }
    }
}
