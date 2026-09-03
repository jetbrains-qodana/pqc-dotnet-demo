using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.Classic;

/// <summary>
/// Key handling for the document signing and key-wrapping service. Nothing here is broken today;
/// all of it is broken by a cryptographically relevant quantum computer.
/// </summary>
/// <remarks>
/// Demonstrates: RSA and DSA reached through eight different kinds of evidence -- the abstract
/// factory, the platform subclasses, CNG algorithm identifiers, algorithm OIDs, padding objects
/// that name the key they pad for, the legacy formatter classes, certificate key accessors and
/// CryptoConfig string names. Note that key size never changes the verdict: RSA-4096 is reported
/// exactly like RSA-1024, because Shor's algorithm does not care.
/// </remarks>
internal sealed class RsaKeyVault
{
    /// <summary>The service signing key, generated on first run.</summary>
    public RSA CreateSigningKey()
    {
        // RSA -- not compliant. 4096 bits buys nothing against a quantum adversary.
        return RSA.Create(4096);
    }

    /// <summary>On Windows the key lives in the platform key store.</summary>
    public RSA CreateSigningKeyOnWindows()
    {
        // RSA -- not compliant, named by the platform subclass.
        return new RSACng(3072);
    }

    /// <summary>On Linux it lives in an OpenSSL provider.</summary>
    public RSA CreateSigningKeyOnLinux(RSAParameters parameters)
    {
        // RSA -- not compliant.
        return new RSAOpenSsl(parameters);
    }

    /// <summary>The HSM-backed key is addressed by CNG algorithm identifier.</summary>
    public CngKey OpenHsmKey(string keyName)
    {
        // RSA -- not compliant, named by a CngAlgorithm rather than a type.
        return CngKey.Create(CngAlgorithm.Rsa, keyName);
    }

    /// <summary>Two customers still verify with DSA.</summary>
    public DSA CreateInteropVerificationKey()
    {
        // DSA -- not compliant.
        return DSA.Create(2048);
    }

    /// <summary>Certificate requests record their key algorithm as an OID.</summary>
    public Oid ReadRequestedKeyAlgorithm()
    {
        // 1.2.840.113549.1.1.1 is rsaEncryption -- not compliant. No RSA type appears here.
        return new Oid("1.2.840.113549.1.1.1");
    }

    /// <summary>The PSS variant has its own OID and is the same algorithm underneath.</summary>
    public Oid ReadRequestedPssAlgorithm()
    {
        // 1.2.840.113549.1.1.10 is RSASSA-PSS -- not compliant.
        return new Oid("1.2.840.113549.1.1.10", "RSASSA-PSS");
    }

    /// <summary>The interop profile pins DSA by OID in a constant.</summary>
    public Oid ReadInteropKeyAlgorithm()
    {
        // The OID reaches the sink through a constant: DSA -- not compliant.
        const string DsaOid = "1.2.840.10040.4.1";
        return Oid.FromOidValue(DsaOid, OidGroup.PublicKeyAlgorithm);
    }

    /// <summary>Some peers still offer finite-field Diffie-Hellman.</summary>
    public Oid ReadPeerKeyAgreement()
    {
        // 1.2.840.10046.2.1 is dhpublicnumber: Diffie-Hellman -- not compliant.
        return Oid.FromOidValue("1.2.840.10046.2.1", OidGroup.All);
    }

    /// <summary>
    /// Wraps a content key. The RSA key arrives as a parameter, so the padding object is the only
    /// thing in the method that names an algorithm -- and it names two.
    /// </summary>
    public byte[] WrapContentKey(RSA recipientKey, byte[] contentKey)
    {
        // RSA -- not compliant, from the padding; SHA-256 -- level 5, from the OAEP member.
        return recipientKey.Encrypt(contentKey, RSAEncryptionPadding.OaepSHA256);
    }

    /// <summary>Signs a document digest. Again the key is a parameter and the padding tells all.</summary>
    public byte[] SignDocument(RSA signingKey, byte[] document)
    {
        // RSA -- not compliant, from the padding; SHA-384 -- level 5.
        return signingKey.SignData(document, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
    }

    /// <summary>The 2009 client wrapped keys through the formatter classes.</summary>
    public AsymmetricKeyExchangeFormatter CreateLegacyKeyWrapper(RSA recipientKey)
    {
        // RSA -- not compliant. The formatter names the key it holds.
        return new RSAOAEPKeyExchangeFormatter(recipientKey);
    }

    /// <summary>And verified signatures through the deformatters, which name their digest too.</summary>
    public AsymmetricSignatureDeformatter CreateLegacyVerifier(RSA publicKey)
    {
        var deformatter = new RSAPKCS1SignatureDeformatter(publicKey); // RSA -- not compliant.

        // SHA-1 -- level 1, named as a CryptoConfig string.
        deformatter.SetHashAlgorithm("SHA1");
        return deformatter;
    }

    /// <summary>Pulls the signing key out of the service certificate.</summary>
    public RSA? OpenCertificateSigningKey(X509Certificate2 certificate)
    {
        // RSA -- not compliant, named by the certificate accessor.
        return certificate.GetRSAPrivateKey();
    }

    /// <summary>Reads a peer's verification key, calling the extension in static form.</summary>
    public RSA? ReadPeerVerificationKey(X509Certificate2 certificate)
    {
        // RSA -- not compliant. Calling the extension statically puts the declaring type where the
        // receiver would be, and the analyzer matches it there as well.
        return RSACertificateExtensions.GetRSAPublicKey(certificate);
    }

    /// <summary>Issues a certificate from the service CA.</summary>
    public X509SignatureGenerator CreateIssuingGenerator(RSA caKey)
    {
        // RSA -- not compliant, named by the signature generator factory.
        return X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Builds the CSR the CA expects.</summary>
    public CertificateRequest CreateCertificateRequest(RSA key)
    {
        // RSA -- not compliant, from the padding; SHA-256 -- level 5.
        return new CertificateRequest("CN=vault.contoso.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>The plugin host resolves key algorithms from a manifest name.</summary>
    public AsymmetricAlgorithm? CreatePluginKey()
    {
        // RSA -- not compliant, named as a string.
        return AsymmetricAlgorithm.Create("RSA");
    }

    /// <summary>
    /// A legacy signature description names its key algorithm and its digest as CryptoConfig
    /// names, in properties rather than at a call.
    /// </summary>
    public SignatureDescription DescribeLegacySignature()
    {
        return new SignatureDescription
        {
            KeyAlgorithm = "System.Security.Cryptography.DSA", // DSA -- not compliant.
            DigestAlgorithm = "SHA1"                           // SHA-1 -- level 1.
        };
    }
}
