using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Modern;

/// <summary>
/// Content encryption for documents written by the current client.
/// </summary>
/// <remarks>
/// Demonstrates: the analyzer does not stop at "compliant / not compliant". AES survives the
/// transition, but Grover's algorithm halves its effective strength, so each key size lands on a
/// different NIST security level (IR 8547) -- and the level is read from whatever names the key
/// size, whether that is a PBE member, an algorithm OID or a PKCS#12 export parameter. Where the
/// key size is not named at all, the analyzer reports the strongest reading rather than guessing.
/// </remarks>
internal sealed class AesContentCipher
{
    /// <summary>Document bodies are sealed with AES-256-GCM.</summary>
    public AesGcm CreateContentCipher(byte[] key)
    {
        // AES -- level 5. The key size is not named here, so the strongest reading is reported.
        return new AesGcm(key, tagSizeInBytes: 16);
    }

    /// <summary>Thumbnails use CCM to match the mobile client.</summary>
    public AesCcm CreateThumbnailCipher(byte[] key)
    {
        // AES -- level 5.
        return new AesCcm(key);
    }

    /// <summary>The bulk re-encryption tool works in CBC for streaming.</summary>
    public SymmetricAlgorithm CreateBulkCipher()
    {
        // AES -- level 5.
        var cipher = Aes.Create();
        cipher.KeySize = 256;
        return cipher;
    }

    /// <summary>
    /// One mobile build negotiated ChaCha20-Poly1305. Solid today, but it is not a NIST algorithm
    /// and IR 8547 gives it no post-quantum standing.
    /// </summary>
    public ChaCha20Poly1305 CreateMobileCipher(byte[] key)
    {
        // ChaCha20 -- not compliant.
        return new ChaCha20Poly1305(key);
    }

    /// <summary>
    /// Three tenants, three key sizes, three different verdicts from the same API. This is the
    /// clearest single demonstration of level discrimination.
    /// </summary>
    public PbeParameters TenantEncryptionParameters(string tenantTier)
    {
        return tenantTier switch
        {
            // AES-128 -- level 1. Post-quantum compliant, but the weakest level NIST recognises.
            "basic" => new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 100_000),

            // AES-192 -- level 3.
            "business" => new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, 100_000),

            // AES-256 -- level 5.
            _ => new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 210_000),
        };
    }

    /// <summary>The envelope header records its content cipher as an OID, key size included.</summary>
    public EnvelopedCms WrapWithAes128(byte[] document)
    {
        var content = new ContentInfo(document);

        // 2.16.840.1.101.3.4.1.2 is aes128-CBC: AES-128 -- level 1, read out of the OID arc.
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid("2.16.840.1.101.3.4.1.2")));
    }

    /// <summary>The same header, one arc over, is a different level.</summary>
    public EnvelopedCms WrapWithAes256(byte[] document)
    {
        var content = new ContentInfo(document);

        // 2.16.840.1.101.3.4.1.42 is aes256-CBC: AES-256 -- level 5.
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid("2.16.840.1.101.3.4.1.42")));
    }

    /// <summary>Key wrapping has its own OIDs on the same arc, and the same levels.</summary>
    public byte[] EncodeKeyWrapAlgorithm()
    {
        // 2.16.840.1.101.3.4.1.28 is aes192-wrap: AES-192 -- level 3.
        return CryptoConfig.EncodeOID("2.16.840.1.101.3.4.1.28");
    }

    /// <summary>Exports a signing certificate the way the current tooling does.</summary>
    public byte[] ExportModernPfx(X509Certificate2 certificate, string password)
    {
        // AES-256 -- level 5; SHA-256 -- level 5. Both read off the one export parameter.
        return certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password);
    }

    /// <summary>The plugin host resolves its content cipher by name.</summary>
    public SymmetricAlgorithm? CreatePluginCipher()
    {
        // AES -- level 5, named as a string.
        return SymmetricAlgorithm.Create("AES");
    }

    /// <summary>
    /// Padding mode selection. Not reported: a padding mode is the same whichever cipher applies
    /// it, so it names no algorithm.
    /// </summary>
    public PaddingMode SelectPadding() => PaddingMode.PKCS7;
}
