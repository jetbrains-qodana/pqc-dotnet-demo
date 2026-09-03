using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace PqcDotnetDemo.Modern;

/// <summary>
/// Digests, message authentication and key derivation as the current client does them.
/// </summary>
/// <remarks>
/// Demonstrates: digests are levelled on preimage resistance (NIST SP 800-107), which is the
/// property a digest inside an HMAC or a KDF actually relies on -- so SHA-256 and SHA3-512 both
/// land on level 5 while SHA3-224 lands on level 3, and SHAKE128 on level 2 despite being part of
/// the SHA-3 family. Also demonstrates how many distinct spellings the analyzer reads a digest
/// from: the hash class, the HMAC class, the KMAC class, a <see cref="HashAlgorithmName"/> member,
/// a <see cref="CngAlgorithm"/> member, a CryptoConfig string and a digest OID.
/// </remarks>
internal static class DigestAndMacServices
{
    /// <summary>Content addressing for documents written by the current client.</summary>
    public static byte[] ComputeDocumentId(byte[] document)
    {
        // SHA-256 -- level 5.
        return SHA256.HashData(document);
    }

    /// <summary>The archive manifest is chained with SHA-384.</summary>
    public static byte[] ComputeManifestDigest(byte[] manifest)
    {
        // SHA-384 -- level 5.
        return SHA384.HashData(manifest);
    }

    /// <summary>The new audit log uses SHA-3.</summary>
    public static byte[] ComputeAuditDigest(byte[] entry)
    {
        // SHA3-256 -- level 5.
        return SHA3_256.HashData(entry);
    }

    /// <summary>
    /// The short tenant fingerprint is truncated SHA-3. .NET ships no SHA3-224 class, so the
    /// index records it as a CryptoConfig name -- which the analyzer reads just as well.
    /// </summary>
    public static string? ResolveTenantFingerprintDigest()
    {
        // SHA3-224 -- level 3. Same family as the line above, two levels lower.
        return CryptoConfig.MapNameToOID("SHA3-224");
    }

    /// <summary>Variable-length ids come from an extendable-output function.</summary>
    public static byte[] ComputeVariableLengthId(byte[] seed, int length)
    {
        // SHAKE128 -- level 2. Its 128-bit capacity is what sets the level, not the SHA-3 badge.
        return Shake128.HashData(seed, length);
    }

    /// <summary>The long variant, for key material.</summary>
    public static byte[] ComputeVariableLengthKeyMaterial(byte[] seed, int length)
    {
        // SHAKE256 -- level 5.
        return Shake256.HashData(seed, length);
    }

    /// <summary>Replication messages are authenticated with HMAC-SHA-256.</summary>
    public static byte[] AuthenticateReplicationMessage(byte[] key, byte[] message)
    {
        // SHA-256 -- level 5, named by the HMAC class.
        return HMACSHA256.HashData(key, message);
    }

    /// <summary>The SHA-3 HMAC, for peers that negotiate it.</summary>
    public static byte[] AuthenticateWithSha3(byte[] key, byte[] message)
    {
        // SHA3-384 -- level 5.
        return HMACSHA3_384.HashData(key, message);
    }

    /// <summary>Tenant-scoped MACs use KMAC, which is keyed SHAKE.</summary>
    public static byte[] AuthenticateTenantMessage(byte[] key, byte[] message)
    {
        // KMAC128 runs on SHAKE128 -- level 2, which is the level the analyzer reports.
        return Kmac128.HashData(key, message, outputLength: 32);
    }

    /// <summary>The high-assurance tier uses the 256-bit variant instead.</summary>
    public static byte[] AuthenticateHighAssuranceMessage(byte[] key, byte[] message)
    {
        // KMACXOF256 runs on SHAKE256 -- level 5.
        return KmacXof256.HashData(key, message, outputLength: 64);
    }

    /// <summary>Session keys are expanded from the agreed secret with HKDF.</summary>
    public static byte[] ExpandSessionKeys(byte[] secret, byte[] salt, byte[] info)
    {
        // SHA-384 -- level 5.
        return HKDF.DeriveKey(HashAlgorithmName.SHA384, secret, outputLength: 64, salt, info);
    }

    /// <summary>Current password hashing, with the digest written down this time.</summary>
    public static byte[] HashPassword(string password, byte[] salt)
    {
        // SHA-256 -- level 5. Compare LegacyDigestService.HashPasswordTheOriginalWay, where the
        // very same class derives on SHA-1 without naming it.
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA256, 32);
    }

    /// <summary>Per-purpose keys are split off the master key with SP 800-108.</summary>
    public static byte[] DeriveSubkey(byte[] masterKey, byte[] label, byte[] context)
    {
        // SHA-512 -- level 5.
        return SP800108HmacCounterKdf.DeriveBytes(masterKey, HashAlgorithmName.SHA512, label, context, 32);
    }

    /// <summary>The generic entry points take the digest as a value, and are covered the same way.</summary>
    public static byte[] ComputeConfiguredDigest(byte[] document)
    {
        // SHA-512 -- level 5.
        return CryptographicOperations.HashData(HashAlgorithmName.SHA512, document);
    }

    /// <summary>Streaming digests over chunked uploads.</summary>
    public static IncrementalHash CreateUploadDigest()
    {
        // SHA3-512 -- level 5.
        return IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
    }

    /// <summary>Streaming MAC over the same upload.</summary>
    public static IncrementalHash CreateUploadMac(byte[] key)
    {
        // SHA-256 -- level 5.
        return IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
    }

    /// <summary>
    /// The digest is chosen once at startup and used later. The analyzer reports it where it is
    /// named, so the finding lands on the assignment rather than on the call.
    /// </summary>
    public static byte[] ComputeDigestWithConfiguredAlgorithm(byte[] document)
    {
        // SHA-512 -- level 5, reported here.
        var configured = HashAlgorithmName.SHA512;

        // Nothing is reported on this line; it names no algorithm of its own.
        return CryptographicOperations.HashData(configured, document);
    }

    /// <summary>On Windows the signing key carries its digest as a CNG property.</summary>
    [SupportedOSPlatform("windows")]
    public static ECDsaCng ConfigureWindowsSigningKey()
    {
        var key = new ECDsaCng(); // ECDSA -- not compliant.

        // SHA-256 -- level 5, named by a CngAlgorithm in a property assignment.
        key.HashAlgorithm = CngAlgorithm.Sha256;
        return key;
    }

    /// <summary>The index resolves digests from CryptoConfig names.</summary>
    public static HashAlgorithm? CreateIndexDigest()
    {
        // SHA-256 -- level 5. "SHA-256" with the dash is a distinct spelling, and resolved too.
        return HashAlgorithm.Create("SHA-256");
    }

    /// <summary>Keyed digests are resolved by name as well.</summary>
    public static KeyedHashAlgorithm? CreateIndexMac()
    {
        // SHA-384 -- level 5, read out of an HMAC class name.
        return KeyedHashAlgorithm.Create("HMACSHA384");
    }

    /// <summary>Signature files name their digest by OID.</summary>
    public static HashAlgorithmName ReadSignatureDigest()
    {
        // 2.16.840.1.101.3.4.2.9 is SHA3-384 -- level 5.
        return HashAlgorithmName.FromOid("2.16.840.1.101.3.4.2.9");
    }

    /// <summary>A truncated SHA-2 variant, named by OID and carrying its own level.</summary>
    public static Oid ReadTruncatedDigestOid()
    {
        // 2.16.840.1.101.3.4.2.5 is SHA-512/224 -- level 3.
        return new Oid("2.16.840.1.101.3.4.2.5", "SHA-512/224");
    }

    /// <summary>The digest name that goes into the CNG key blob.</summary>
    public static CngAlgorithm BuildCngDigestName()
    {
        // SHA-384 -- level 5.
        return new CngAlgorithm("SHA384");
    }
}
