using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.PostQuantum;

/// <summary>
/// The replacement session key agreement: ML-KEM (FIPS 203), the target of the migration.
/// </summary>
/// <remarks>
/// Demonstrates: the analyzer reports compliant algorithms too, not only problems. That is what
/// makes it an inventory rather than a linter -- you can answer "which of our services already
/// speak ML-KEM, and at which parameter set?" from the same scan that finds the ECDH. Each
/// parameter set carries its own NIST level, and where a key is loaded without naming one, the
/// finding names the family instead of inventing a level.
/// </remarks>
internal sealed class MlKemKeyExchange
{
    /// <summary>The tier every tenant gets by default.</summary>
    public MLKem CreateSessionKey()
    {
        // ML-KEM-768 -- level 3.
        return MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    }

    /// <summary>Constrained devices negotiate the smallest parameter set.</summary>
    public MLKem CreateEmbeddedSessionKey()
    {
        // ML-KEM-512 -- level 1. Compliant, but the weakest level -- worth surfacing in an
        // inventory even though nothing is wrong with it.
        return MLKem.GenerateKey(MLKemAlgorithm.MLKem512);
    }

    /// <summary>The high-assurance tier.</summary>
    public MLKem CreateHighAssuranceSessionKey()
    {
        // ML-KEM-1024 -- level 5.
        return MLKem.GenerateKey(MLKemAlgorithm.MLKem1024);
    }

    /// <summary>The parameter set is chosen from the tenant tier before the key is generated.</summary>
    public MLKem CreateSessionKeyForTier(string tier)
    {
        // Each parameter set is reported where it is named, on these three lines:
        var parameterSet = tier switch
        {
            "embedded" => MLKemAlgorithm.MLKem512,   // ML-KEM-512 -- level 1.
            "high" => MLKemAlgorithm.MLKem1024,      // ML-KEM-1024 -- level 5.
            _ => MLKemAlgorithm.MLKem768,            // ML-KEM-768 -- level 3.
        };

        // ML-KEM -- level 5. The type still names the family here; the parameter set was reported
        // above, where the code actually chose it.
        return MLKem.GenerateKey(parameterSet);
    }

    /// <summary>Encapsulates a content key to a peer's published encapsulation key.</summary>
    public MLKem ImportPeerEncapsulationKey(byte[] encodedKey)
    {
        // ML-KEM-768 -- level 3.
        return MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encodedKey);
    }

    /// <summary>
    /// Peers that publish PEM do not name the parameter set at the call site -- it is inside the
    /// encoded key.
    /// </summary>
    public MLKem ImportPeerKeyFromPem(string pem)
    {
        // ML-KEM -- level 5. The family is all the code says, and the analyzer reports exactly
        // that rather than guessing a parameter set.
        return MLKem.ImportFromPem(pem);
    }

    /// <summary>On Windows the decapsulation key lives in the platform store.</summary>
    public CngKey OpenPlatformDecapsulationKey()
    {
        // ML-KEM -- level 5, named by a CngAlgorithm.
        return CngKey.Create(CngAlgorithm.MLKem);
    }

    /// <summary>The platform wrapper names the family and leaves the parameter set to the CNG key.</summary>
    public MLKem OpenPlatformKey(CngKey key)
    {
        // ML-KEM -- level 5.
        return new MLKemCng(key);
    }

    /// <summary>The Linux build reaches the same key through an OpenSSL handle.</summary>
    public MLKem OpenOpenSslKey(SafeEvpPKeyHandle handle)
    {
        // ML-KEM -- level 5.
        return new MLKemOpenSsl(handle);
    }

    /// <summary>The peer profile records the parameter set as an OID.</summary>
    public Oid ReadPeerKemAlgorithm()
    {
        // 2.16.840.1.101.3.4.4.2 is id-alg-ml-kem-768: ML-KEM-768 -- level 3, from the OID alone.
        return new Oid("2.16.840.1.101.3.4.4.2");
    }

    /// <summary>The strongest parameter set has its own OID one arc over.</summary>
    public Oid ReadHighAssuranceKemAlgorithm()
    {
        // 2.16.840.1.101.3.4.4.3 is ML-KEM-1024 -- level 5.
        return new Oid("2.16.840.1.101.3.4.4.3");
    }

    /// <summary>Reads a peer's encapsulation key out of its KEM certificate.</summary>
    public MLKem? ReadCertificateKey(X509Certificate2 certificate)
    {
        // ML-KEM -- level 5, named by the certificate accessor.
        return certificate.GetMLKemPublicKey();
    }

    /// <summary>Establishes a shared secret with a peer. Neither line names an algorithm.</summary>
    public (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(MLKem peerKey)
    {
        peerKey.Encapsulate(out var ciphertext, out var sharedSecret);
        return (ciphertext, sharedSecret);
    }
}
