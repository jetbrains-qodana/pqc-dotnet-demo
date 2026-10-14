using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.PostQuantum;

internal static class MlKemKeyExchange
{
    public static MLKem CreateSessionKey()
    {
        return MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    }

    public static MLKem CreateEmbeddedSessionKey()
    {
        return MLKem.GenerateKey(MLKemAlgorithm.MLKem512);
    }

    public static MLKem CreateHighAssuranceSessionKey()
    {
        return MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
    }

    public static MLKem CreateSessionKeyForTier(string tier)
    {
        var parameterSet = tier switch
        {
            "embedded" => MLKemAlgorithm.MLKem512,
            "high" => MLKemAlgorithm.MLKem1024,
            _ => MLKemAlgorithm.MLKem768
        };

        return MLKem.GenerateKey(parameterSet);
    }

    public static MLKem ImportPeerEncapsulationKey(byte[] encodedKey)
    {
        return MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encodedKey);
    }

    public static MLKem ImportPeerKeyFromPem(string pem)
    {
        return MLKem.ImportFromPem(pem);
    }

    [SupportedOSPlatform("windows")]
    public static CngKey OpenPlatformDecapsulationKey()
    {
        return CngKey.Create(CngAlgorithm.MLKem);
    }

    [SupportedOSPlatform("windows")]
    public static MLKem OpenPlatformKey(CngKey key)
    {
        return new MLKemCng(key);
    }

    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("macos")]
    public static MLKem OpenOpenSslKey(SafeEvpPKeyHandle handle)
    {
        return new MLKemOpenSsl(handle);
    }

    public static Oid ReadPeerKemAlgorithm()
    {
        // ML-KEM-768
        return new Oid("2.16.840.1.101.3.4.4.2");
    }

    public static Oid ReadHighAssuranceKemAlgorithm()
    {
        // ML-KEM-1024
        return new Oid("2.16.840.1.101.3.4.4.3");
    }

    public static MLKem? ReadCertificateKey(X509Certificate2 certificate)
    {
        return certificate.GetMLKemPublicKey();
    }

    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(MLKem peerKey)
    {
        peerKey.Encapsulate(out var ciphertext, out var sharedSecret);
        return (ciphertext, sharedSecret);
    }
}
