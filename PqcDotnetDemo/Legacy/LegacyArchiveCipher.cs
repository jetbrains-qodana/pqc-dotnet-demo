using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Legacy;

/// <summary>
/// Reads and re-wraps documents from the 2009-era archive. Everything in here predates the
/// migration and is exactly the sort of code an inventory is supposed to surface.
/// </summary>
/// <remarks>
/// Demonstrates: symmetric ciphers with no post-quantum standing at all, reached through class
/// names, factory methods, algorithm OIDs, <see cref="CryptoConfig"/> string names and PKCS#12
/// export parameters.
/// </remarks>
internal static class LegacyArchiveCipher
{
    /// <summary>Volumes written before 2012 are single-DES; the oldest are the smallest.</summary>
    public static SymmetricAlgorithm OpenOldestVolume()
    {
        // DES -- not compliant. The class name and the factory both name it.
        return DES.Create();
    }

    public static SymmetricAlgorithm OpenArchiveVolume(int volumeYear)
    {
        if (volumeYear < 2012)
        {
            // Triple DES -- not compliant.
            return new TripleDESCryptoServiceProvider();
        }

        // Triple DES again, this time through the factory and the abstract base.
        return TripleDES.Create();
    }

    /// <summary>Attachments in the mail archive were wrapped with RC2 at 128 bits.</summary>
    public static SymmetricAlgorithm OpenMailAttachment()
    {
        // RC2 -- not compliant, named by construction with an object initializer.
        return new RC2CryptoServiceProvider { EffectiveKeySize = 128 };
    }

    /// <summary>
    /// The volume header records its cipher as a CryptoConfig name rather than a type.
    /// </summary>
    public static object? OpenVolumeByHeaderName()
    {
        // The name reaches the detection through a local: "3DES" is Triple DES -- not compliant.
        const string headerName = "3DES";
        return CryptoConfig.CreateFromName(headerName);
    }

    /// <summary>Rijndael is how AES was spelled when this code was written.</summary>
    public static SymmetricAlgorithm OpenVolumeWrittenByTheOldClient()
    {
        // Rijndael resolves to AES -- level 5, because no key size is named here and the analyzer
        // reads an unqualified AES conservatively as its strongest parameter set.
        return new RijndaelManaged { KeySize = 256 };
    }

    /// <summary>Rejects the DES keys the 2009 key ceremony is known to have produced.</summary>
    public static bool IsUnusableArchiveKey(byte[] key)
    {
        // Naming DES without encrypting with it still names DES -- not compliant.
        return DES.IsWeakKey(key) || DES.IsSemiWeakKey(key);
    }

    /// <summary>
    /// Password-based encryption for the archive manifest. The parameters name both the cipher
    /// and the hash deriving its key, so one call yields two findings.
    /// </summary>
    public static PbeParameters ManifestEncryptionParameters()
    {
        // Triple DES -- not compliant; SHA-1 -- level 1.
        return new PbeParameters(
            PbeEncryptionAlgorithm.TripleDes3KeyPkcs12,
            HashAlgorithmName.SHA1,
            iterationCount: 2000);
    }

    /// <summary>The CMS envelopes in the archive record their cipher as an OID.</summary>
    public static EnvelopedCms WrapForLegacyRecipient(byte[] document)
    {
        var content = new ContentInfo(document);

        // 1.2.840.113549.3.7 is Triple DES-CBC -- not compliant. The OID alone is enough; no
        // cipher class appears anywhere in this method.
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid("1.2.840.113549.3.7")));
    }

    /// <summary>An even older envelope format, whose cipher OID arrives from the header table.</summary>
    public static EnvelopedCms WrapForAncientRecipient(byte[] document)
    {
        // The OID is tainted through a local before it reaches the sink: RC4 -- not compliant.
        const string cipherOid = "1.2.840.113549.3.4";

        var content = new ContentInfo(document);
        return new EnvelopedCms(content, new AlgorithmIdentifier(new Oid(cipherOid)));
    }

    /// <summary>Exports an archive signing certificate in the format the old tooling accepts.</summary>
    public static byte[] ExportLegacyPfx(X509Certificate2 certificate, string password)
    {
        // The export parameters name the cipher and the hash together:
        // Triple DES -- not compliant; SHA-1 -- level 1.
        return certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, password);
    }

    /// <summary>Derives the volume key the way the 2009 client did.</summary>
    public static byte[] DeriveVolumeKey(string password, byte[] salt)
    {
        var derivation = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);

        // One call naming both a cipher and the hash deriving its key:
        // RC2 -- not compliant; SHA-256 -- level 5.
        return derivation.CryptDeriveKey("RC2", "SHA256", 128, new byte[8]);
    }
}
