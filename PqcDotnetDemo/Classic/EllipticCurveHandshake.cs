using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Classic;

/// <summary>
/// The session handshake between the archive service and its replication peers.
/// </summary>
/// <remarks>
/// Demonstrates: elliptic-curve key agreement and signatures. This is the family with the
/// shortest remaining life -- an ECDH session key recorded today is decryptable the day a
/// quantum computer arrives, which is the whole "store now, decrypt later" argument. Note the
/// deliberate silence on curve names: <c>nistP256</c> says which curve a key sits on, not which
/// algorithm consumes it, so the analyzer reads the algorithm and leaves the curve alone.
/// </remarks>
internal static class EllipticCurveHandshake
{
    /// <summary>Our half of the session key agreement.</summary>
    public static ECDiffieHellman CreateSessionKey()
    {
        // ECDH -- not compliant. The curve argument is not what is being reported.
        return ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
    }

    /// <summary>On Windows the agreement key is a CNG key.</summary>
    [SupportedOSPlatform("windows")]
    public static ECDiffieHellman CreateSessionKeyOnWindows()
    {
        // ECDH -- not compliant.
        return new ECDiffieHellmanCng(521);
    }

    /// <summary>The peer-facing signing key.</summary>
    public static ECDsa CreateHandshakeSigningKey()
    {
        // ECDSA -- not compliant.
        return ECDsa.Create(ECCurve.NamedCurves.nistP256);
    }

    /// <summary>The Linux build reaches the same key through OpenSSL.</summary>
    [UnsupportedOSPlatform("windows")]
    public static ECDsa CreateHandshakeSigningKeyOnLinux()
    {
        // ECDSA -- not compliant. Brainpool changes nothing about the verdict.
        return new ECDsaOpenSsl(ECCurve.NamedCurves.brainpoolP256r1);
    }

    /// <summary>The HSM addresses its curve keys by CNG algorithm identifier.</summary>
    [SupportedOSPlatform("windows")]
    public static CngKey OpenHsmSigningKey()
    {
        // ECDSA -- not compliant, named by a CngAlgorithm.
        return CngKey.Create(CngAlgorithm.ECDsaP384, "handshake", new CngKeyCreationParameters());
    }

    /// <summary>The agreement key identifier is read from configuration first.</summary>
    [SupportedOSPlatform("windows")]
    public static CngKey OpenHsmAgreementKey()
    {
        // The analyzer follows the identifier through the local: ECDH -- not compliant.
        var algorithm = CngAlgorithm.ECDiffieHellmanP521;
        return CngKey.Create(algorithm);
    }

    /// <summary>Derives the session key from the agreed secret.</summary>
    public static byte[] DeriveSessionKey(ECDiffieHellman self, ECDiffieHellmanPublicKey peer)
    {
        // SHA-384 -- level 5. The ECDH on the parameter type is not a use site; the key was
        // created somewhere the analyzer already looked.
        return self.DeriveKeyFromHash(peer, HashAlgorithmName.SHA384);
    }

    /// <summary>Derives the message authentication key from the same secret.</summary>
    public static byte[] DeriveMacKey(ECDiffieHellman self, ECDiffieHellmanPublicKey peer, byte[] salt)
    {
        // SHA-256 -- level 5.
        return self.DeriveKeyFromHmac(peer, HashAlgorithmName.SHA256, salt);
    }

    /// <summary>The peer profile records its key algorithm as an OID.</summary>
    public static Oid ReadPeerKeyAlgorithm()
    {
        // 1.2.840.10045.2.1 is id-ecPublicKey. It does not say whether the key signs or agrees,
        // so this is reported as Elliptic Curve -- not compliant either way.
        return new Oid("1.2.840.10045.2.1", "ECC");
    }

    /// <summary>Two peers offer Ed25519 instead.</summary>
    public static Oid ReadEdwardsKeyAlgorithm()
    {
        // 1.3.101.112 is Ed25519 -- not compliant.
        return new Oid("1.3.101.112");
    }

    /// <summary>And one offers X25519 for key agreement.</summary>
    public static Oid ReadMontgomeryKeyAgreement()
    {
        // 1.3.101.110 is X25519 -- not compliant.
        return new Oid("1.3.101.110");
    }

    /// <summary>A peer key assembled from its encoded parts rather than parsed from a certificate.</summary>
    public static PublicKey AssemblePeerPublicKey(byte[] encodedParameters, byte[] encodedKey)
    {
        // Elliptic Curve -- not compliant, from the OID alone.
        return new PublicKey(
            new Oid("1.2.840.10045.2.1"),
            new AsnEncodedData(encodedParameters),
            new AsnEncodedData(encodedKey));
    }

    /// <summary>An Ed25519 private key loaded from a PKCS#8 blob.</summary>
    public static Pkcs8PrivateKeyInfo LoadEdwardsPrivateKey(byte[] encodedKey)
    {
        // Ed25519 -- not compliant.
        return new Pkcs8PrivateKeyInfo(new Oid("1.3.101.112"), null, encodedKey);
    }

    /// <summary>Pulls the handshake verification key out of the peer certificate.</summary>
    public static ECDsa? ReadPeerVerificationKey(X509Certificate2 certificate)
    {
        // ECDSA -- not compliant.
        return certificate.GetECDsaPublicKey();
    }

    /// <summary>
    /// Reads a peer's agreement key. Only <see cref="PublicKey"/> reaches ECDH from a certificate;
    /// there is no certificate extension method for it.
    /// </summary>
    public static ECDiffieHellman? ReadPeerAgreementKey(PublicKey publicKey)
    {
        // ECDH -- not compliant.
        return publicKey.GetECDiffieHellmanPublicKey();
    }

    /// <summary>Signs the peer's short-lived handshake certificate.</summary>
    public static X509SignatureGenerator CreateHandshakeGenerator(ECDsa key)
    {
        // ECDSA -- not compliant.
        return X509SignatureGenerator.CreateForECDsa(key);
    }

    /// <summary>
    /// Curve selection. Nothing in here is reported: a curve OID names the curve, not the
    /// algorithm, and says nothing about the security level either.
    /// </summary>
    public static ECCurve SelectCurve(bool useSecp256r1)
    {
        return useSecp256r1
            ? ECCurve.NamedCurves.nistP256
            : ECCurve.CreateFromOid(new Oid("1.2.840.10045.3.1.7"));
    }
}
