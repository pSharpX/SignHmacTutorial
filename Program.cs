// See https://aka.ms/new-console-template for more information

using System;
using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.Extensions.Configuration;

CreateIdentity();

static void CreateIdentity()
{
    Console.WriteLine("Azure Communication Services - Sign an HTTP request Tutorial");

    // Build a config object, using env vars and JSON providers.
    IConfiguration config = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .AddEnvironmentVariables()
        .Build();

    // Get values from the config given their key and their target type.
    Settings settings = config.GetRequiredSection("Settings").Get<Settings>();

    string resourceEndpoint = settings.Acs.Endpoint;
    // Create a uri you are going to call.
    var requestUri = new Uri($"{resourceEndpoint}/identities?api-version=2021-03-07");
    // Endpoint identities?api-version=2021-03-07 accepts list of scopes as a body
    var body = new[] { "chat" }; 
    var serializedBody = JsonConvert.SerializeObject(body);
    var requestMessage = new HttpRequestMessage(HttpMethod.Post, requestUri)
    {
        Content = new StringContent(serializedBody, Encoding.UTF8)
    };
    // Specify the 'x-ms-date' header as the current UTC timestamp according to the RFC1123 standard
    var date = DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture);
    // Get the host name corresponding with the 'host' header.
    var host = requestUri.Authority;
    // Compute a content hash for the 'x-ms-content-sha256' header.
    var contentHash = ComputeContentHash(serializedBody);

    // Prepare a string to sign.
    var stringToSign = $"POST\n{requestUri.PathAndQuery}\n{date};{host};{contentHash}";
    // Compute the signature.
    var signature = ComputeSignature(settings.Acs.AccessKey, stringToSign);
    // Concatenate the string, which will be used in the authorization header.
    var authorizationHeader = $"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={signature}";

    // Add a date header.
    requestMessage.Headers.Add("x-ms-date", date);

    // Add a host header.
    // In C#, the 'host' header is added automatically by the 'HttpClient'. However, this step may be required on other platforms such as Node.js.

    // Add a content hash header.
    requestMessage.Headers.Add("x-ms-content-sha256", contentHash);

    // Add an authorization header.
    requestMessage.Headers.Add("Authorization", authorizationHeader);

    HttpClient httpClient = new HttpClient
    {
        BaseAddress = requestUri
    };
    Console.WriteLine(stringToSign);
    Console.WriteLine(date);
    Console.WriteLine(contentHash);
    Console.WriteLine(authorizationHeader);

    var response = httpClient.SendAsync(requestMessage).Result;
    var responseString = response.Content.ReadAsStringAsync().Result;
    Console.WriteLine(response.IsSuccessStatusCode);
    Console.WriteLine(responseString);
}

static string ComputeContentHash(string content)
{
    using (var sha256 = SHA256.Create())
    {
        byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(content));
        return Convert.ToBase64String(hashedBytes);
    }
}

static string ComputeSignature(string secret, string stringToSign)
{
    using (var hmacsha256 = new HMACSHA256(Convert.FromBase64String(secret)))
    {
        var bytes = Encoding.ASCII.GetBytes(stringToSign);
        var hashedBytes = hmacsha256.ComputeHash(bytes);
        return Convert.ToBase64String(hashedBytes);
    }
}
