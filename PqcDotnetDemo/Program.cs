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
        var document = "quarterly-report.pdf"u8.ToArray();
        Console.WriteLine($"  legacy document id (MD5)      {Convert.ToHexString(LegacyDigestService.ComputeDocumentId(document))}");
        Console.WriteLine($"  current document id (SHA-256) {Convert.ToHexString(DigestAndMacServices.ComputeDocumentId(document))[..32]}...");

        using var bulk = AesContentCipher.CreateBulkCipher();
        Console.WriteLine($"  bulk cipher                   {bulk.GetType().Name}, {bulk.KeySize}-bit key");

        Console.WriteLine($"  negotiated transport          {LegacyTransportPolicy.CurrentClientOptions("peer.contoso.example").EnabledSslProtocols}");

        using var signingKey = RsaKeyVault.CreateSigningKey();
        Console.WriteLine($"  classical signing key         RSA-{signingKey.KeySize}");

        RunPostQuantumPaths(document);

        // The rest of the inventory is exercised in bulk
        InventorySweep.Run();
    }

    private static void RunPostQuantumPaths(byte[] document)
    {
        using var sessionKey = MlKemKeyExchange.CreateSessionKey();
        var (ciphertext, sharedSecret) = MlKemKeyExchange.Encapsulate(sessionKey);
        Console.WriteLine($"  ML-KEM-768 encapsulation      {ciphertext.Length}-byte ciphertext, {sharedSecret.Length}-byte secret");

        using var documentKey = MlDsaSigner.CreateDocumentSigningKey();
        var signature = MlDsaSigner.SignDocument(documentKey, document);
        Console.WriteLine($"  ML-DSA-65 signature           {signature.Length} bytes, verifies: {MlDsaSigner.VerifyDocument(documentKey, document, signature)}");
    }
}
