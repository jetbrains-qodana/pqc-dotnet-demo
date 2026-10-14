using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace PqcDotnetDemo.Modern;

internal static class DigestAndMacServices
{
    public static byte[] ComputeDocumentId(byte[] document)
    {
        return SHA256.HashData(document);
    }

    public static byte[] ComputeManifestDigest(byte[] manifest)
    {
        return SHA384.HashData(manifest);
    }

    public static byte[] ComputeAuditDigest(byte[] entry)
    {
        return SHA3_256.HashData(entry);
    }

    public static string? ResolveTenantFingerprintDigest()
    {
        return CryptoConfig.MapNameToOID("SHA3-224");
    }

    public static byte[] ComputeVariableLengthId(byte[] seed, int length)
    {
        return Shake128.HashData(seed, length);
    }

    public static byte[] ComputeVariableLengthKeyMaterial(byte[] seed, int length)
    {
        return Shake256.HashData(seed, length);
    }

    public static byte[] AuthenticateReplicationMessage(byte[] key, byte[] message)
    {
        return HMACSHA256.HashData(key, message);
    }

    public static byte[] AuthenticateWithSha3(byte[] key, byte[] message)
    {
        return HMACSHA3_384.HashData(key, message);
    }

    public static byte[] AuthenticateTenantMessage(byte[] key, byte[] message)
    {
        // SHAKE128
        return Kmac128.HashData(key, message, outputLength: 32);
    }

    public static byte[] AuthenticateHighAssuranceMessage(byte[] key, byte[] message)
    {
        // SHAKE256
        return KmacXof256.HashData(key, message, outputLength: 64);
    }

    public static byte[] ExpandSessionKeys(byte[] secret, byte[] salt, byte[] info)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA384, secret, outputLength: 64, salt, info);
    }

    public static byte[] HashPassword(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA256, 32);
    }

    public static byte[] DeriveSubkey(byte[] masterKey, byte[] label, byte[] context)
    {
        return SP800108HmacCounterKdf.DeriveBytes(masterKey, HashAlgorithmName.SHA512, label, context, 32);
    }

    public static byte[] ComputeConfiguredDigest(byte[] document)
    {
        return CryptographicOperations.HashData(HashAlgorithmName.SHA512, document);
    }

    public static IncrementalHash CreateUploadDigest()
    {
        return IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512);
    }

    public static IncrementalHash CreateUploadMac(byte[] key)
    {
        return IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
    }

    public static byte[] ComputeDigestWithConfiguredAlgorithm(byte[] document)
    {
        var configured = HashAlgorithmName.SHA512;

        return CryptographicOperations.HashData(configured, document);
    }

    [SupportedOSPlatform("windows")]
    public static ECDsaCng ConfigureWindowsSigningKey()
    {
        var key = new ECDsaCng();
        key.HashAlgorithm = CngAlgorithm.Sha256;
        return key;
    }

    public static HashAlgorithm? CreateIndexDigest()
    {
        return HashAlgorithm.Create("SHA-256");
    }

    public static KeyedHashAlgorithm? CreateIndexMac()
    {
        return KeyedHashAlgorithm.Create("HMACSHA384");
    }

    public static HashAlgorithmName ReadSignatureDigest()
    {
        // SHA3-384
        return HashAlgorithmName.FromOid("2.16.840.1.101.3.4.2.9");
    }

    public static Oid ReadTruncatedDigestOid()
    {
        // SHA-512/224
        return new Oid("2.16.840.1.101.3.4.2.5", "SHA-512/224");
    }

    public static CngAlgorithm BuildCngDigestName()
    {
        // SHA-384
        return new CngAlgorithm("SHA384");
    }
}
