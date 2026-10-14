using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Classic;

internal static class RsaKeyVault
{
    public static RSA CreateSigningKey()
    {
        return RSA.Create(4096);
    }

    [SupportedOSPlatform("windows")]
    public static RSA CreateSigningKeyOnWindows()
    {
        return new RSACng(3072);
    }

    [UnsupportedOSPlatform("windows")]
    public static RSA CreateSigningKeyOnLinux(RSAParameters parameters)
    {
        return new RSAOpenSsl(parameters);
    }

    [SupportedOSPlatform("windows")]
    public static CngKey OpenHsmKey(string keyName)
    {
        return CngKey.Create(CngAlgorithm.Rsa, keyName);
    }

    public static DSA CreateInteropVerificationKey()
    {
        return DSA.Create(2048);
    }

    public static Oid ReadRequestedKeyAlgorithm()
    {
        // rsaEncryption
        return new Oid("1.2.840.113549.1.1.1");
    }

    public static Oid ReadRequestedPssAlgorithm()
    {
        // RSASSA-PSS
        return new Oid("1.2.840.113549.1.1.10", "RSASSA-PSS");
    }

    public static Oid ReadInteropKeyAlgorithm()
    {
        // DSA
        const string dsaOid = "1.2.840.10040.4.1";
        return Oid.FromOidValue(dsaOid, OidGroup.PublicKeyAlgorithm);
    }

    public static Oid ReadPeerKeyAgreement()
    {
        // Diffie-Hellman
        return Oid.FromOidValue("1.2.840.10046.2.1", OidGroup.All);
    }

    public static byte[] WrapContentKey(RSA recipientKey, byte[] contentKey)
    {
        return recipientKey.Encrypt(contentKey, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] SignDocument(RSA signingKey, byte[] document)
    {
        return signingKey.SignData(document, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
    }

    public static AsymmetricKeyExchangeFormatter CreateLegacyKeyWrapper(RSA recipientKey)
    {
        return new RSAOAEPKeyExchangeFormatter(recipientKey);
    }

    public static AsymmetricSignatureDeformatter CreateLegacyVerifier(RSA publicKey)
    {
        var deformatter = new RSAPKCS1SignatureDeformatter(publicKey);

        deformatter.SetHashAlgorithm("SHA1");
        return deformatter;
    }

    public static RSA? OpenCertificateSigningKey(X509Certificate2 certificate)
    {
        return certificate.GetRSAPrivateKey();
    }

    public static X509SignatureGenerator CreateIssuingGenerator(RSA caKey)
    {
        return X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1);
    }

    public static CertificateRequest CreateCertificateRequest(RSA key)
    {
        return new CertificateRequest("CN=vault.contoso.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static AsymmetricAlgorithm? CreatePluginKey()
    {
        return AsymmetricAlgorithm.Create("RSA");
    }
}
