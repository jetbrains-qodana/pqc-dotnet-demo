using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Legacy;

/// <summary>
/// Content addressing, password storage and integrity checks as the archive originally shipped them.
/// </summary>
/// <remarks>
/// Demonstrates: broken and weakened digests reached through hash classes, obsolete subclasses,
/// HMAC classes, <see cref="HashAlgorithmName"/> members, digest OIDs, string names held in
/// properties, and a key derivation whose hash is implied by the overload rather than written down.
/// </remarks>
internal static class LegacyDigestService
{
    /// <summary>Document ids in the archive are MD5 over the raw bytes.</summary>
    public static byte[] ComputeDocumentId(byte[] document)
    {
        // MD5 -- not compliant.
        return MD5.HashData(document);
    }

    /// <summary>The replication protocol compares SHA-1 chunk digests.</summary>
    public static byte[] ComputeChunkDigest(byte[] chunk)
    {
        // SHA-1 -- level 1. Collision-broken, but the analyzer levels digests on preimage
        // resistance, which is what a content digest actually relies on.
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(chunk);
    }

    /// <summary>The Windows build of the 2009 client used the CSP subclasses directly.</summary>
    public static byte[] ComputeDocumentIdOnWindows(byte[] document)
    {
        // MD5 again, this time through the obsolete provider subclass -- not compliant.
        using var md5 = new MD5CryptoServiceProvider();
        return md5.ComputeHash(document);
    }

    public static byte[] ComputeChunkDigestOnWindows(byte[] chunk)
    {
        // SHA-1 through the managed subclass -- level 1.
        using var sha1 = new SHA1Managed();
        return sha1.ComputeHash(chunk);
    }

    /// <summary>Replication messages are authenticated with HMAC-MD5.</summary>
    public static byte[] AuthenticateReplicationMessage(byte[] key, byte[] message)
    {
        // MD5 under an HMAC -- not compliant. The HMAC class names the digest it runs on.
        return HMACMD5.HashData(key, message);
    }

    /// <summary>Session cookies are signed with HMAC-SHA-1.</summary>
    public static byte[] SignSessionCookie(byte[] key, byte[] cookie)
    {
        // SHA-1 -- level 1.
        using var hmac = new HMACSHA1(key);
        return hmac.ComputeHash(cookie);
    }

    /// <summary>
    /// The original password hashing. Every PBKDF2 overload taking fewer than four arguments
    /// derives on HMAC-SHA-1 without naming it anywhere.
    /// </summary>
    public static byte[] HashPasswordTheOriginalWay(string password, byte[] salt)
    {
        // SHA-1 -- level 1, implied by the overload. Nothing in this line spells out a hash.
        using var derivation = new Rfc2898DeriveBytes(password, salt, 100_000);
        return derivation.GetBytes(32);
    }

    /// <summary>An even older derivation that names its hash as a string.</summary>
    public static byte[] HashPasswordTheOlderWay(string password, byte[] salt)
    {
        // SHA-1 -- level 1, named as a CryptoConfig string.
        using var derivation = new PasswordDeriveBytes(password, salt, "SHA1", 100);
        return derivation.GetBytes(32);
    }

    /// <summary>The migration tool lets the operator pick the digest by name.</summary>
    public static byte[] HashPasswordWithConfiguredDigest(string password, byte[] salt)
    {
        // MD5 -- not compliant, held in a property rather than passed to a call.
        using var derivation = new PasswordDeriveBytes(password, salt) { HashName = "MD5" };
        return derivation.GetBytes(32);
    }

    /// <summary>Legacy OAEP mask generation, whose digest also lives in a property.</summary>
    public static PKCS1MaskGenerationMethod BuildLegacyMaskGenerator()
    {
        // SHA-1 -- level 1.
        return new PKCS1MaskGenerationMethod { HashName = "SHA1" };
    }

    /// <summary>The archive index resolves digests from CryptoConfig names.</summary>
    public static HashAlgorithm? CreateIndexDigest()
    {
        // MD5 -- not compliant, created by name.
        return HashAlgorithm.Create("MD5");
    }

    /// <summary>Some index entries predate even MD5 and record MD2.</summary>
    public static string? ResolveAncientDigestOid()
    {
        // MD2 -- not compliant. Named, not used: naming is enough for an inventory.
        return CryptoConfig.MapNameToOID("MD2");
    }

    /// <summary>Signature files in the archive name their digest by OID.</summary>
    public static HashAlgorithmName ReadSignatureDigest()
    {
        // 1.2.840.113549.2.5 is MD5 -- not compliant.
        return HashAlgorithmName.FromOid("1.2.840.113549.2.5");
    }

    /// <summary>And some name SHA-1's OID instead.</summary>
    public static bool TryReadSignatureDigest(out HashAlgorithmName digest)
    {
        // 1.3.14.3.2.26 is SHA-1 -- level 1.
        return HashAlgorithmName.TryFromOid("1.3.14.3.2.26", out digest);
    }

    /// <summary>Subject key identifiers were built with SHA-1 when these certificates were issued.</summary>
    public static X509SubjectKeyIdentifierExtension BuildLegacyKeyIdentifier(PublicKey publicKey)
    {
        // SHA-1 -- level 1, named by an enum member that is not a HashAlgorithmName.
        return new X509SubjectKeyIdentifierExtension(
            publicKey,
            X509SubjectKeyIdentifierHashAlgorithm.CapiSha1,
            critical: false);
    }

    /// <summary>The digest name arrives from configuration, not from a literal at the call site.</summary>
    public static HashAlgorithm? CreateConfiguredDigest()
    {
        // The analyzer follows the name through the local: SHA-1 -- level 1.
        const string configured = "SHA1";
        return HashAlgorithm.Create(configured);
    }
}
