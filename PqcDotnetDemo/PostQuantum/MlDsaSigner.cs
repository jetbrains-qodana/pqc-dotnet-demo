using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.PostQuantum;

internal static class MlDsaSigner
{
    public static MLDsa CreateDocumentSigningKey()
    {
        return MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    }

    public static MLDsa CreateHandshakeSigningKey()
    {
        return MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
    }

    public static MLDsa CreateRootSigningKey()
    {
        return MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
    }

    public static SlhDsa CreateFirmwareSigningKey()
    {
        return SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_256s);
    }

    public static SlhDsa CreateSecondaryFirmwareSigningKey()
    {
        return SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake192f);
    }

    public static SlhDsa CreateBootloaderSigningKey()
    {
        return SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
    }

    public static MLDsa ImportPeerVerificationKey(byte[] encodedKey)
    {
        return MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa87, encodedKey);
    }

    public static MLDsa ImportPeerVerificationKeyFromSpki(byte[] subjectPublicKeyInfo)
    {
        return MLDsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
    }

    public static SlhDsa ImportFirmwareVerificationKey(string pem)
    {
        return SlhDsa.ImportFromPem(pem);
    }

    public static bool IsFirmwareSigningAvailable()
    {
        return SlhDsa.IsSupported;
    }

    [SupportedOSPlatform("windows")]
    public static CngKey OpenPlatformSigningKey()
    {
        return CngKey.Create(CngAlgorithm.MLDsa);
    }

    [SupportedOSPlatform("windows")]
    public static MLDsa OpenPlatformKey(CngKey key)
    {
        return new MLDsaCng(key);
    }

    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("macos")]
    public static SlhDsa OpenFirmwareKeyOnLinux(SafeEvpPKeyHandle handle)
    {
        return new SlhDsaOpenSsl(handle);
    }

    public static Oid ReadSignatureAlgorithm()
    {
        // ML-DSA-65
        return new Oid("2.16.840.1.101.3.4.3.18");
    }

    public static Oid ReadPreHashSignatureAlgorithm()
    {
        // ML-DSA-44
        return new Oid("2.16.840.1.101.3.4.3.32");
    }

    public static Oid ReadFirmwareSignatureAlgorithm()
    {
        // SLH-DSA-SHAKE-256
        return new Oid("2.16.840.1.101.3.4.3.30");
    }

    public static MLDsa? ReadCertificateKey(X509Certificate2 certificate)
    {
        return certificate.GetMLDsaPublicKey();
    }

    public static X509SignatureGenerator CreateIssuingGenerator(MLDsa caKey)
    {
        return X509SignatureGenerator.CreateForMLDsa(caKey);
    }

    public static X509SignatureGenerator CreateFirmwareIssuingGenerator(SlhDsa caKey)
    {
        return X509SignatureGenerator.CreateForSlhDsa(caKey);
    }

    public static byte[] SignDocument(MLDsa key, byte[] document) => key.SignData(document);

    public static bool VerifyDocument(MLDsa key, byte[] document, byte[] signature) =>
        key.VerifyData(document, signature);
}
