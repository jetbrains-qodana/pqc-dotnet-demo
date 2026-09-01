using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.PostQuantum;

/// <summary>
/// The replacement signature schemes: ML-DSA (FIPS 204) for documents, SLH-DSA (FIPS 205) for
/// firmware and anything else with a twenty-year verification horizon.
/// </summary>
/// <remarks>
/// Demonstrates: two post-quantum signature families side by side, with their parameter sets on
/// different levels -- and the fact that "SHA2" or "SHAKE" in an SLH-DSA parameter set name does
/// not turn the finding into a digest finding. Also shows the pre-hash OIDs, which sit fifteen
/// arcs along from the plain ones and are the same parameter set at the same level.
/// </remarks>
internal sealed class MlDsaSigner
{
    /// <summary>The document signing key every tenant gets.</summary>
    public MLDsa CreateDocumentSigningKey()
    {
        // ML-DSA-65 -- level 3.
        return MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    }

    /// <summary>Short-lived handshake signatures use the smallest parameter set.</summary>
    public MLDsa CreateHandshakeSigningKey()
    {
        // ML-DSA-44 -- level 2.
        return MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
    }

    /// <summary>The tenant root signing key.</summary>
    public MLDsa CreateRootSigningKey()
    {
        // ML-DSA-87 -- level 5.
        return MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
    }

    /// <summary>
    /// Firmware images are signed with SLH-DSA: slower and much larger, but hash-based, so it
    /// rests on different assumptions than the lattice schemes above.
    /// </summary>
    public SlhDsa CreateFirmwareSigningKey()
    {
        // SLH-DSA-SHA2-256 -- level 5. The "SHA2" is part of the parameter set name, not a
        // separate digest finding.
        return SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_256s);
    }

    /// <summary>The SHAKE-based variant, for the second firmware line.</summary>
    public SlhDsa CreateSecondaryFirmwareSigningKey()
    {
        // SLH-DSA-SHAKE-192 -- level 3.
        return SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaShake192f);
    }

    /// <summary>The smallest SLH-DSA parameter set, used by the bootloader.</summary>
    public SlhDsa CreateBootloaderSigningKey()
    {
        // SLH-DSA-SHA2-128 -- level 1.
        return SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
    }

    /// <summary>Loads a published verification key whose parameter set is named at the call.</summary>
    public MLDsa ImportPeerVerificationKey(byte[] encodedKey)
    {
        // ML-DSA-87 -- level 5.
        return MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa87, encodedKey);
    }

    /// <summary>
    /// And one whose parameter set is inside the encoded key rather than at the call site.
    /// </summary>
    public MLDsa ImportPeerVerificationKeyFromSpki(byte[] subjectPublicKeyInfo)
    {
        // ML-DSA -- level 5: the family, because that is all the code names.
        return MLDsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
    }

    /// <summary>Firmware verification keys arrive as PEM.</summary>
    public SlhDsa ImportFirmwareVerificationKey(string pem)
    {
        // SLH-DSA -- level 5.
        return SlhDsa.ImportFromPem(pem);
    }

    /// <summary>Feature detection, which names the family without signing anything.</summary>
    public bool IsFirmwareSigningAvailable()
    {
        // SLH-DSA -- level 5. An inventory wants this line: it is evidence the code path exists.
        return SlhDsa.IsSupported;
    }

    /// <summary>On Windows the document signing key lives in the platform store.</summary>
    public CngKey OpenPlatformSigningKey()
    {
        // ML-DSA -- level 5, named by a CngAlgorithm.
        return CngKey.Create(CngAlgorithm.MLDsa);
    }

    /// <summary>The platform wrapper over that key.</summary>
    public MLDsa OpenPlatformKey(CngKey key)
    {
        // ML-DSA -- level 5.
        return new MLDsaCng(key);
    }

    /// <summary>The firmware key on Linux.</summary>
    public SlhDsa OpenFirmwareKeyOnLinux(SafeEvpPKeyHandle handle)
    {
        // SLH-DSA -- level 5.
        return new SlhDsaOpenSsl(handle);
    }

    /// <summary>The signature file records its algorithm as an OID.</summary>
    public Oid ReadSignatureAlgorithm()
    {
        // 2.16.840.1.101.3.4.3.18 is id-ml-dsa-65: ML-DSA-65 -- level 3.
        return new Oid("2.16.840.1.101.3.4.3.18");
    }

    /// <summary>
    /// Large documents are signed over an externally computed digest, which is a different OID
    /// for the same parameter set.
    /// </summary>
    public Oid ReadPreHashSignatureAlgorithm()
    {
        // 2.16.840.1.101.3.4.3.32 is id-hash-ml-dsa-44-with-sha512: ML-DSA-44 -- level 2. Fifteen
        // arcs along from the plain parameter set, and the same level.
        return new Oid("2.16.840.1.101.3.4.3.32");
    }

    /// <summary>Firmware signature files name SLH-DSA by OID.</summary>
    public Oid ReadFirmwareSignatureAlgorithm()
    {
        // 2.16.840.1.101.3.4.3.30 is SLH-DSA-SHAKE-256 -- level 5.
        return new Oid("2.16.840.1.101.3.4.3.30");
    }

    /// <summary>Reads a peer's verification key out of its certificate.</summary>
    public MLDsa? ReadCertificateKey(X509Certificate2 certificate)
    {
        // ML-DSA -- level 5, named by the certificate accessor.
        return certificate.GetMLDsaPublicKey();
    }

    /// <summary>Issues short-lived tenant certificates from the post-quantum CA.</summary>
    public X509SignatureGenerator CreateIssuingGenerator(MLDsa caKey)
    {
        // ML-DSA -- level 5.
        return X509SignatureGenerator.CreateForMLDsa(caKey);
    }

    /// <summary>The firmware CA signs with SLH-DSA instead.</summary>
    public X509SignatureGenerator CreateFirmwareIssuingGenerator(SlhDsa caKey)
    {
        // SLH-DSA -- level 5.
        return X509SignatureGenerator.CreateForSlhDsa(caKey);
    }

    /// <summary>Signing and verifying name no algorithm; the key was made where they are reported.</summary>
    public byte[] SignDocument(MLDsa key, byte[] document) => key.SignData(document);

    public bool VerifyDocument(MLDsa key, byte[] document, byte[] signature) =>
        key.VerifyData(document, signature);
}
