using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Legacy;

internal static class LegacyDigestService
{
    public static byte[] ComputeDocumentId(byte[] document)
    {
        return MD5.HashData(document);
    }

    public static byte[] ComputeChunkDigest(byte[] chunk)
    {
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(chunk);
    }

    public static byte[] ComputeDocumentIdOnWindows(byte[] document)
    {
        using var md5 = new MD5CryptoServiceProvider();
        return md5.ComputeHash(document);
    }

    public static byte[] ComputeChunkDigestOnWindows(byte[] chunk)
    {
        using var sha1 = new SHA1Managed();
        return sha1.ComputeHash(chunk);
    }

    public static byte[] AuthenticateReplicationMessage(byte[] key, byte[] message)
    {
        return HMACMD5.HashData(key, message);
    }

    public static byte[] SignSessionCookie(byte[] key, byte[] cookie)
    {
        using var hmac = new HMACSHA1(key);
        return hmac.ComputeHash(cookie);
    }

    public static byte[] HashPasswordTheOriginalWay(string password, byte[] salt)
    {
        using var derivation = new Rfc2898DeriveBytes(password, salt, 100_000);
        return derivation.GetBytes(32);
    }

    public static byte[] HashPasswordTheOlderWay(string password, byte[] salt)
    {
        using var derivation = new PasswordDeriveBytes(password, salt, "SHA1", 100);
        return derivation.GetBytes(32);
    }

    public static HashAlgorithm? CreateIndexDigest()
    {
        return HashAlgorithm.Create("MD5");
    }

    public static string? ResolveAncientDigestOid()
    {
        return CryptoConfig.MapNameToOID("MD2");
    }

    public static HashAlgorithmName ReadSignatureDigest()
    {
        // MD5
        return HashAlgorithmName.FromOid("1.2.840.113549.2.5");
    }

    public static bool TryReadSignatureDigest(out HashAlgorithmName digest)
    {
        // SHA-1
        return HashAlgorithmName.TryFromOid("1.3.14.3.2.26", out digest);
    }

    public static X509SubjectKeyIdentifierExtension BuildLegacyKeyIdentifier(PublicKey publicKey)
    {
        return new X509SubjectKeyIdentifierExtension(
            publicKey,
            X509SubjectKeyIdentifierHashAlgorithm.CapiSha1,
            critical: false);
    }

    public static HashAlgorithm? CreateConfiguredDigest()
    {
        const string configured = "SHA1";
        return HashAlgorithm.Create(configured);
    }
}
