using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Legacy;

internal static class LegacyArchiveCipher
{
    public static SymmetricAlgorithm OpenOldestVolume()
    {
        return DES.Create();
    }

    public static SymmetricAlgorithm OpenArchiveVolume(int volumeYear)
    {
        if (volumeYear < 2012)
        {
            return new TripleDESCryptoServiceProvider();
        }
        return TripleDES.Create();
    }

    public static SymmetricAlgorithm OpenMailAttachment()
    {
        return new RC2CryptoServiceProvider { EffectiveKeySize = 128 };
    }

    public static object? OpenVolumeByHeaderName()
    {
        const string headerName = "3DES";
        return CryptoConfig.CreateFromName(headerName);
    }

    public static PbeParameters ManifestEncryptionParameters()
    {
        return new PbeParameters(
            PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
            HashAlgorithmName.SHA1,
            iterationCount: 2000);
    }

    public static EnvelopedCms WrapForLegacyRecipient(byte[] document)
    {
        var content = new ContentInfo(document);

        // Triple DES-CBC
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid("1.2.840.113549.3.7")));
    }

    public static EnvelopedCms WrapForAncientRecipient(byte[] document)
    {
        // RC4
        const string cipherOid = "1.2.840.113549.3.4";

        var content = new ContentInfo(document);
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid(cipherOid)));
    }

    public static byte[] ExportLegacyPfx(X509Certificate2 certificate, string password)
    {
        return certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, password);
    }

    public static byte[] DeriveVolumeKey(string password, byte[] salt)
    {
        var derivation = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);

        return derivation.CryptDeriveKey("RC2", "SHA256", 128, new byte[8]);
    }
}
