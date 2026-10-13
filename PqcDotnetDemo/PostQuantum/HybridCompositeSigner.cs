using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PqcDotnetDemo.PostQuantum;

internal static class HybridCompositeSigner
{
    public static CompositeMLDsa CreateTransitionalDocumentKey()
    {
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithRSA3072Pss);
    }

    public static CompositeMLDsa CreateTransitionalHandshakeKey()
    {
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
    }

    public static CompositeMLDsa CreateTransitionalRootKey()
    {
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithEd448);
    }

    public static CompositeMLDsa CreateBrainpoolPairedKey()
    {
        return CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaBrainpoolP256r1);
    }

    public static CompositeMLDsa CreateKeyForProfile(bool preferEdwards)
    {
        var pairing = preferEdwards
            ? CompositeMLDsaAlgorithm.MLDsa44WithEd25519
            : CompositeMLDsaAlgorithm.MLDsa44WithRSA2048Pss;

        return CompositeMLDsa.GenerateKey(pairing);
    }

    public static CompositeMLDsa ImportPeerVerificationKey(byte[] encodedKey)
    {
        return CompositeMLDsa.ImportCompositeMLDsaPublicKey(
            CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521,
            encodedKey);
    }

    public static bool IsTransitionalProfileAvailable()
    {
        return CompositeMLDsa.IsAlgorithmSupported(CompositeMLDsaAlgorithm.MLDsa44WithEd25519);
    }

    public static CompositeMLDsa? ReadCertificateKey(X509Certificate2 certificate)
    {
        return certificate.GetCompositeMLDsaPublicKey();
    }

    public static X509SignatureGenerator CreateIssuingGenerator(CompositeMLDsa caKey)
    {
        return X509SignatureGenerator.CreateForCompositeMLDsa(caKey);
    }
}
