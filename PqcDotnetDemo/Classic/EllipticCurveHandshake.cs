using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Classic;

internal static class EllipticCurveHandshake
{
    public static ECDiffieHellman CreateSessionKey()
    {
        return ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
    }

    [SupportedOSPlatform("windows")]
    public static ECDiffieHellman CreateSessionKeyOnWindows()
    {
        return new ECDiffieHellmanCng(521);
    }

    public static ECDsa CreateHandshakeSigningKey()
    {
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    [UnsupportedOSPlatform("windows")]
    public static ECDsa CreateHandshakeSigningKeyOnLinux()
    {
        return new ECDsaOpenSsl(ECCurve.NamedCurves.brainpoolP256r1);
    }

    [SupportedOSPlatform("windows")]
    public static CngKey OpenHsmSigningKey()
    {
        return CngKey.Create(CngAlgorithm.ECDsaP384, "handshake", new CngKeyCreationParameters());
    }

    [SupportedOSPlatform("windows")]
    public static CngKey OpenHsmAgreementKey()
    {
        var algorithm = CngAlgorithm.ECDiffieHellmanP521;
        return CngKey.Create(algorithm);
    }

    public static byte[] DeriveSessionKey(ECDiffieHellman self, ECDiffieHellmanPublicKey peer)
    {
        return self.DeriveKeyFromHash(peer, HashAlgorithmName.SHA384);
    }

    public static byte[] DeriveMacKey(ECDiffieHellman self, ECDiffieHellmanPublicKey peer, byte[] salt)
    {
        return self.DeriveKeyFromHmac(peer, HashAlgorithmName.SHA256, salt);
    }

    public static Oid ReadPeerKeyAlgorithm()
    {
        //  Elliptic Curve
        return new Oid("1.2.840.10045.2.1", "ECC");
    }

    public static Oid ReadEdwardsKeyAlgorithm()
    {
        // Ed25519
        return new Oid("1.3.101.112");
    }

    public static Oid ReadMontgomeryKeyAgreement()
    {
        // X25519
        return new Oid("1.3.101.110");
    }

    public static PublicKey AssemblePeerPublicKey(byte[] encodedParameters, byte[] encodedKey)
    {
        // Elliptic Curve
        return new PublicKey(
            new Oid("1.2.840.10045.2.1"),
            new AsnEncodedData(encodedParameters),
            new AsnEncodedData(encodedKey));
    }

    public static Pkcs8PrivateKeyInfo LoadEdwardsPrivateKey(byte[] encodedKey)
    {
        // Ed25519
        return new Pkcs8PrivateKeyInfo(new Oid("1.3.101.112"), null, encodedKey);
    }

    public static ECDsa? ReadPeerVerificationKey(X509Certificate2 certificate)
    {
        return certificate.GetECDsaPublicKey();
    }

    public static ECDiffieHellman? ReadPeerAgreementKey(PublicKey publicKey)
    {
        return publicKey.GetECDiffieHellmanPublicKey();
    }

    public static X509SignatureGenerator CreateHandshakeGenerator(ECDsa key)
    {
        return X509SignatureGenerator.CreateForECDsa(key);
    }
}
