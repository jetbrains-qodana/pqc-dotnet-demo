using System.Net;
using System.Net.Security;
using System.Security.Authentication;

namespace PqcDotnetDemo.Legacy;

/// <summary>
/// Transport settings for the replication peers and the on-premises index server.
/// </summary>
/// <remarks>
/// Demonstrates: protocol versions are inventoried the same way algorithms are. Everything below
/// TLS 1.3 is reported, because no earlier version carries a standardised hybrid key exchange --
/// including TLS 1.2, which most policy scanners treat as fine. The analyzer matches the enum
/// member itself, so every API that consumes one is covered without enumerating them.
/// </remarks>
internal static class LegacyTransportPolicy
{
    /// <summary>The oldest replication peer has never been upgraded.</summary>
    public static async Task ConnectToAncientPeerAsync(SslStream stream, string host)
    {
        // SSL 3 -- not compliant.
        await stream.AuthenticateAsClientAsync(host, null, SslProtocols.Ssl3, checkCertificateRevocation: false);
    }

    /// <summary>The index server negotiated TLS 1.0 when it was commissioned.</summary>
    public static async Task ConnectToIndexServerAsync(SslStream stream, string host)
    {
        // TLS 1.0 -- not compliant.
        await stream.AuthenticateAsClientAsync(host, null, SslProtocols.Tls, checkCertificateRevocation: false);
    }

    /// <summary>Current production floor: TLS 1.2, and still reported.</summary>
    public static SslClientAuthenticationOptions CurrentClientOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = host,

            // TLS 1.2 -- not compliant. This is the finding that usually starts the conversation.
            EnabledSslProtocols = SslProtocols.Tls12
        };
    }

    /// <summary>What the fleet should look like after the migration.</summary>
    public static SslClientAuthenticationOptions TargetClientOptions(string host)
    {
        return new SslClientAuthenticationOptions
        {
            TargetHost = host,

            // TLS 1.3 -- compliant, and deliberately not reported.
            EnabledSslProtocols = SslProtocols.Tls13
        };
    }

    /// <summary>The inbound listener still accepts TLS 1.1 for two remaining clients.</summary>
    public static SslServerAuthenticationOptions ListenerOptions()
    {
        // TLS 1.1 -- not compliant.
        return new SslServerAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls11 };
    }

    /// <summary>
    /// A single member naming two versions: <c>Default</c> is <c>Ssl3 | Tls</c>.
    /// </summary>
    public static SslProtocols LegacyDefault()
    {
        // Two findings on one member: SSL 3 -- not compliant, and TLS 1.0 -- not compliant.
        return SslProtocols.Default;
    }

    /// <summary>A flags combination is read member by member.</summary>
    public static SslProtocols MigrationWindowProtocols()
    {
        // TLS 1.2 -- not compliant, is reported; the TLS 1.3 in the same expression is not.
        return SslProtocols.Tls12 | SslProtocols.Tls13;
    }

    /// <summary>The pre-.NET Core process-wide switch, set at startup.</summary>
    public static void ApplyProcessWidePolicy()
    {
        // The legacy enum is covered too: TLS 1.0 -- not compliant.
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
    }
}
