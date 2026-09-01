using System.Security.Cryptography;
using PqcDotnetDemo.Classic;
using PqcDotnetDemo.Legacy;
using PqcDotnetDemo.Modern;
using PqcDotnetDemo.PostQuantum;

namespace PqcDotnetDemo;

/// <summary>
/// A service midway through a post-quantum migration.
/// </summary>
internal static class Program
{
    private static void Main()
    {
        var legacyDigests = new LegacyDigestService();
        var document = "quarterly-report.pdf"u8.ToArray();
        Console.WriteLine($"  legacy document id (MD5)      {Convert.ToHexString(legacyDigests.ComputeDocumentId(document))}");

        var modernDigests = new DigestAndMacServices();
        Console.WriteLine($"  current document id (SHA-256) {Convert.ToHexString(modernDigests.ComputeDocumentId(document))[..32]}...");

        var cipher = new AesContentCipher();
        using var bulk = cipher.CreateBulkCipher();
        Console.WriteLine($"  bulk cipher                   {bulk.GetType().Name}, {bulk.KeySize}-bit key");

        var transport = new LegacyTransportPolicy();
        Console.WriteLine($"  negotiated transport          {transport.CurrentClientOptions("peer.contoso.example").EnabledSslProtocols}");

        var vault = new RsaKeyVault();
        using var signingKey = vault.CreateSigningKey();
        Console.WriteLine($"  classical signing key         RSA-{signingKey.KeySize}");

        RunPostQuantumPaths(document);
    }

    private static void RunPostQuantumPaths(byte[] document)
    {
        // ML-KEM -- level 5, and ML-DSA -- level 5. Feature probing names both families, and the
        // scan reports them: an inventory wants to know the code path exists.
        if (!MLKem.IsSupported || !MLDsa.IsSupported)
        {
            Console.WriteLine("  post-quantum paths            skipped (no ML-KEM/ML-DSA provider on this machine)");
            return;
        }

        var exchange = new MlKemKeyExchange();
        using var sessionKey = exchange.CreateSessionKey();
        var (ciphertext, sharedSecret) = exchange.Encapsulate(sessionKey);
        Console.WriteLine($"  ML-KEM-768 encapsulation      {ciphertext.Length}-byte ciphertext, {sharedSecret.Length}-byte secret");

        var signer = new MlDsaSigner();
        using var documentKey = signer.CreateDocumentSigningKey();
        var signature = signer.SignDocument(documentKey, document);
        Console.WriteLine($"  ML-DSA-65 signature           {signature.Length} bytes, verifies: {signer.VerifyDocument(documentKey, document, signature)}");
    }
}
