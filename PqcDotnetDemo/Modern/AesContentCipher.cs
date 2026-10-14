using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Modern;

internal static class AesContentCipher
{
    public static AesGcm CreateContentCipher(byte[] key)
    {
        return new AesGcm(key, tagSizeInBytes: 16);
    }

    public static AesCcm CreateThumbnailCipher(byte[] key)
    {
        return new AesCcm(key);
    }

    public static SymmetricAlgorithm CreateBulkCipher()
    {
        var cipher = Aes.Create();
        cipher.KeySize = 256;
        return cipher;
    }

    public static ChaCha20Poly1305 CreateMobileCipher(byte[] key)
    {
        return new ChaCha20Poly1305(key);
    }

    public static PbeParameters TenantEncryptionParameters(string tenantTier)
    {
        return tenantTier switch
        {
            "basic" => new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 100_000),
            "business" => new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, 100_000),
            _ => new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA512, 210_000)
        };
    }

    public static EnvelopedCms WrapWithAes128(byte[] document)
    {
        var content = new ContentInfo(document);

        // aes128-CBC
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid("2.16.840.1.101.3.4.1.2")));
    }

    public static EnvelopedCms WrapWithAes256(byte[] document)
    {
        var content = new ContentInfo(document);

        // aes256-CBC
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid("2.16.840.1.101.3.4.1.42")));
    }

    public static byte[] EncodeKeyWrapAlgorithm()
    {
        // aes192-wrap
        return CryptoConfig.EncodeOID("2.16.840.1.101.3.4.1.28");
    }

    public static byte[] ExportModernPfx(X509Certificate2 certificate, string password)
    {
        return certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password);
    }

    public static SymmetricAlgorithm? CreatePluginCipher()
    {
        return SymmetricAlgorithm.Create("AES");
    }
}
