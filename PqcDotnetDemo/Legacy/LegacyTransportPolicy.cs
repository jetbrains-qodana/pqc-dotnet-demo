using System.Net;
using System.Net.Security;
using System.Security.Authentication;

namespace PqcDotnetDemo.Legacy;

internal static class LegacyTransportPolicy
{
    public static async Task ConnectToAncientPeerAsync(SslStream stream, string host)
    {
        await stream.AuthenticateAsClientAsync(host, null, SslProtocols.Ssl3, checkCertificateRevocation: false);
    }

    public static async Task ConnectToIndexServerAsync(SslStream stream, string host)
    {
        await stream.AuthenticateAsClientAsync(host, null, SslProtocols.Tls, checkCertificateRevocation: false);
    }

    public static SslClientAuthenticationOptions CurrentClientOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls12
        };
    }

    public static SslClientAuthenticationOptions TargetClientOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls13
        };
    }

    public static SslServerAuthenticationOptions ListenerOptions()
    {
        return new SslServerAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls11 };
    }

    public static SslProtocols LegacyDefault()
    {
        // SSL 3.0 or TLS 1.0.
        return SslProtocols.Default;
    }

    public static SslProtocols MigrationWindowProtocols()
    {
        return SslProtocols.Tls12 | SslProtocols.Tls13;
    }

    public static void ApplyProcessWidePolicy()
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
    }
}
