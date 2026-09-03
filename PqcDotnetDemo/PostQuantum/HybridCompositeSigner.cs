using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.PostQuantum;

/// <summary>
/// Composite ML-DSA: one signature carrying both a post-quantum and a classical component, for
/// the peers and auditors that cannot verify a bare ML-DSA signature yet.
/// </summary>
/// <remarks>
/// Demonstrates: hybrid schemes are recognised as hybrids rather than being split into an
/// unrelated "good" and "bad" finding. The level is the post-quantum component's -- pairing
/// ML-DSA-65 with RSA-3072 does not drag the verdict down to RSA's, because an attacker has to
/// break both halves. Each pairing is one finding naming both components, so an inventory can
/// tell a deliberate hybrid deployment apart from a service that simply still uses RSA.
/// </remarks>
internal static class HybridCompositeSigner
{
    /// <summary>The transitional document signing key, for auditors still on RSA.</summary>
    public static CompositeMLDsa CreateTransitionalDocumentKey()
    {
        // ML-DSA-65 with RSA-3072 -- hybrid, level 3. Reported at the post-quantum component's
        // level, not RSA's.
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss);
    }

    /// <summary>The transitional handshake key, paired with the ECDSA the peers already verify.</summary>
    public static CompositeMLDsa CreateTransitionalHandshakeKey()
    {
        // ML-DSA-44 with ECDSA-P256 -- hybrid, level 2.
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
    }

    /// <summary>The transitional root, at the strongest pairing available.</summary>
    public static CompositeMLDsa CreateTransitionalRootKey()
    {
        // ML-DSA-87 with Ed448 -- hybrid, level 5.
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithEd448);
    }

    /// <summary>One customer pins Brainpool curves in its profile.</summary>
    public static CompositeMLDsa CreateBrainpoolPairedKey()
    {
        // ML-DSA-65 with ECDSA-BrainpoolP256r1 -- hybrid, level 3.
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaBrainpoolP256r1);
    }

    /// <summary>The pairing is read from the tenant profile before the key is generated.</summary>
    public static CompositeMLDsa CreateKeyForProfile(bool preferEdwards)
    {
        // Both pairings are reported here, where the code names them:
        var pairing = preferEdwards
            ? CompositeMLDsaAlgorithm.MLDsa44WithEd25519  // hybrid, level 2.
            : CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pss; // hybrid, level 2.

        return CompositeMLDsa.GenerateKey(pairing);
    }

    /// <summary>Loads a peer's composite verification key, pairing named at the call.</summary>
    public static CompositeMLDsa ImportPeerVerificationKey(byte[] encodedKey)
    {
        // ML-DSA-87 with ECDSA-P521 -- hybrid, level 5.
        return CompositeMLDsa.ImportCompositeMLDsaPublicKey(
            CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521,
            encodedKey);
    }

    /// <summary>Feature probing, which names a pairing without signing with it.</summary>
    public static bool IsTransitionalProfileAvailable()
    {
        // ML-DSA-44 with Ed25519 -- hybrid, level 2.
        return CompositeMLDsa.IsAlgorithmSupported(CompositeMLDsaAlgorithm.MLDsa44WithEd25519);
    }

    /// <summary>Reads a composite key out of a transitional certificate.</summary>
    public static CompositeMLDsa? ReadCertificateKey(X509Certificate2 certificate)
    {
        // Composite ML-DSA, named by the certificate accessor -- a different rule from the plain
        // ML-DSA accessor, so an inventory can separate hybrid deployments from pure ones.
        return certificate.GetCompositeMLDsaPublicKey();
    }

    /// <summary>Issues transitional certificates.</summary>
    public static X509SignatureGenerator CreateIssuingGenerator(CompositeMLDsa caKey)
    {
        // Composite ML-DSA.
        return X509SignatureGenerator.CreateForCompositeMLDsa(caKey);
    }

    /// <summary>
    /// A composite key loaded from PEM. Not reported: the pairing is inside the encoded key, and
    /// with no pairing named there is no level to report -- so the analyzer stays quiet rather
    /// than reporting a hybrid it cannot characterise.
    /// </summary>
    public static CompositeMLDsa ImportPeerKeyFromPem(string pem)
    {
        return CompositeMLDsa.ImportFromPem(pem);
    }
}
