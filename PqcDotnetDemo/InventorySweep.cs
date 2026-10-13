using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PqcDotnetDemo.Classic;
using PqcDotnetDemo.Legacy;
using PqcDotnetDemo.Modern;
using PqcDotnetDemo.PostQuantum;

namespace PqcDotnetDemo;

/// <summary>
/// Calls every member of every demo class exactly once.
/// </summary>
internal static class InventorySweep
{
    private const string Password = "correct-horse-battery-staple";
    private const string PeerHost = "peer.contoso.example";

    private static readonly byte[] Document = [.. "quarterly-report.pdf"u8];
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] Salt = RandomNumberGenerator.GetBytes(16);

    public static void Run()
    {
        Console.WriteLine();
        Console.WriteLine("  inventory sweep -- every member of every demo class is called once");

        using var certificateKey = RsaKeyVault.CreateSigningKey();
        using var certificate = RsaKeyVault
            .CreateCertificateRequest(certificateKey)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        SweepRsaKeyVault(certificate);
        SweepEllipticCurveHandshake(certificate);
        SweepLegacyArchiveCipher(certificate);
        SweepLegacyDigestService(certificate);
        SweepLegacyTransportPolicy();
        SweepAesContentCipher(certificate);
        SweepDigestAndMacServices();
        SweepMlKemKeyExchange(certificate);
        SweepMlDsaSigner(certificate);
        SweepHybridCompositeSigner(certificate);
    }

    private static void SweepRsaKeyVault(X509Certificate2 certificate)
    {
        using var signingKey = RsaKeyVault.CreateSigningKey();
        using var interopKey = RsaKeyVault.CreateInteropVerificationKey();

        RsaKeyVault.ReadRequestedKeyAlgorithm();
        RsaKeyVault.ReadRequestedPssAlgorithm();
        RsaKeyVault.ReadInteropKeyAlgorithm();
        RsaKeyVault.ReadPeerKeyAgreement();
        RsaKeyVault.WrapContentKey(signingKey, Key);
        RsaKeyVault.SignDocument(signingKey, Document);
        RsaKeyVault.CreateLegacyKeyWrapper(signingKey);
        RsaKeyVault.CreateLegacyVerifier(signingKey);
        RsaKeyVault.CreateIssuingGenerator(signingKey);
        RsaKeyVault.OpenCertificateSigningKey(certificate)?.Dispose();
        RsaKeyVault.CreatePluginKey()?.Dispose();

        if (OperatingSystem.IsWindows())
        {
            SweepWindowsRsaKeyVault();
        }
        else
        {
            using var openSslKey = RsaKeyVault.CreateSigningKeyOnLinux(signingKey.ExportParameters(true));
        }

        Done(nameof(RsaKeyVault));
    }

    [SupportedOSPlatform("windows")]
    private static void SweepWindowsRsaKeyVault()
    {
        using var platformKey = RsaKeyVault.CreateSigningKeyOnWindows();
        Probe($"{nameof(RsaKeyVault)}.{nameof(RsaKeyVault.OpenHsmKey)}",
            () => RsaKeyVault.OpenHsmKey("vault-signing").Dispose());
    }

    private static void SweepEllipticCurveHandshake(X509Certificate2 certificate)
    {
        using var self = EllipticCurveHandshake.CreateSessionKey();
        using var peer = EllipticCurveHandshake.CreateSessionKey();
        using var signingKey = EllipticCurveHandshake.CreateHandshakeSigningKey();

        EllipticCurveHandshake.DeriveSessionKey(self, peer.PublicKey);
        EllipticCurveHandshake.DeriveMacKey(self, peer.PublicKey, Salt);
        EllipticCurveHandshake.ReadPeerKeyAlgorithm();
        EllipticCurveHandshake.ReadEdwardsKeyAlgorithm();
        EllipticCurveHandshake.ReadMontgomeryKeyAgreement();
        EllipticCurveHandshake.LoadEdwardsPrivateKey(RandomNumberGenerator.GetBytes(32));
        EllipticCurveHandshake.CreateHandshakeGenerator(signingKey);

        EllipticCurveHandshake.ReadPeerVerificationKey(certificate)?.Dispose();

        var peerPublicKey = PublicKey.CreateFromSubjectPublicKeyInfo(
            peer.PublicKey.ExportSubjectPublicKeyInfo(),
            out _);
        if (peerPublicKey.EncodedParameters is { } encodedParameters)
        {
            var assembled = EllipticCurveHandshake.AssemblePeerPublicKey(
                encodedParameters.RawData,
                peerPublicKey.EncodedKeyValue.RawData);
            EllipticCurveHandshake.ReadPeerAgreementKey(assembled)?.Dispose();
        }

        if (OperatingSystem.IsWindows())
        {
            SweepWindowsEllipticCurveHandshake();
        }
        else
        {
            using var openSslKey = EllipticCurveHandshake.CreateHandshakeSigningKeyOnLinux();
        }

        Done(nameof(EllipticCurveHandshake));
    }

    [SupportedOSPlatform("windows")]
    private static void SweepWindowsEllipticCurveHandshake()
    {
        using var platformKey = EllipticCurveHandshake.CreateSessionKeyOnWindows();
        Probe($"{nameof(EllipticCurveHandshake)}.{nameof(EllipticCurveHandshake.OpenHsmSigningKey)}",
            () => EllipticCurveHandshake.OpenHsmSigningKey().Dispose());
        Probe($"{nameof(EllipticCurveHandshake)}.{nameof(EllipticCurveHandshake.OpenHsmAgreementKey)}",
            () => EllipticCurveHandshake.OpenHsmAgreementKey().Dispose());
    }

    private static void SweepLegacyArchiveCipher(X509Certificate2 certificate)
    {
        using var oldest = LegacyArchiveCipher.OpenOldestVolume();
        using var preTwelve = LegacyArchiveCipher.OpenArchiveVolume(volumeYear: 2009);
        using var postTwelve = LegacyArchiveCipher.OpenArchiveVolume(volumeYear: 2015);
        using var attachment = LegacyArchiveCipher.OpenMailAttachment();

        (LegacyArchiveCipher.OpenVolumeByHeaderName() as IDisposable)?.Dispose();
        LegacyArchiveCipher.ManifestEncryptionParameters();
        LegacyArchiveCipher.WrapForLegacyRecipient(Document);
        LegacyArchiveCipher.WrapForAncientRecipient(Document);
        LegacyArchiveCipher.ExportLegacyPfx(certificate, Password);

        Probe($"{nameof(LegacyArchiveCipher)}.{nameof(LegacyArchiveCipher.DeriveVolumeKey)}",
            () => LegacyArchiveCipher.DeriveVolumeKey(Password, Salt));

        Done(nameof(LegacyArchiveCipher));
    }

    private static void SweepLegacyDigestService(X509Certificate2 certificate)
    {
        LegacyDigestService.ComputeDocumentId(Document);
        LegacyDigestService.ComputeChunkDigest(Document);
        LegacyDigestService.ComputeDocumentIdOnWindows(Document);
        LegacyDigestService.ComputeChunkDigestOnWindows(Document);
        LegacyDigestService.AuthenticateReplicationMessage(Key, Document);
        LegacyDigestService.SignSessionCookie(Key, Document);
        LegacyDigestService.HashPasswordTheOriginalWay(Password, Salt);
        LegacyDigestService.HashPasswordTheOlderWay(Password, Salt);
        LegacyDigestService.ResolveAncientDigestOid();
        LegacyDigestService.ReadSignatureDigest();
        LegacyDigestService.TryReadSignatureDigest(out _);
        LegacyDigestService.BuildLegacyKeyIdentifier(certificate.PublicKey);
        LegacyDigestService.CreateIndexDigest()?.Dispose();
        LegacyDigestService.CreateConfiguredDigest()?.Dispose();

        Done(nameof(LegacyDigestService));
    }

    private static void SweepLegacyTransportPolicy()
    {
        LegacyTransportPolicy.CurrentClientOptions(PeerHost);
        LegacyTransportPolicy.TargetClientOptions(PeerHost);
        LegacyTransportPolicy.ListenerOptions();
        LegacyTransportPolicy.LegacyDefault();
        LegacyTransportPolicy.MigrationWindowProtocols();
        LegacyTransportPolicy.ApplyProcessWidePolicy();

        Probe($"{nameof(LegacyTransportPolicy)}.{nameof(LegacyTransportPolicy.ConnectToAncientPeerAsync)}", () =>
        {
            using var inner = new MemoryStream();
            using var stream = new SslStream(inner);
            LegacyTransportPolicy.ConnectToAncientPeerAsync(stream, PeerHost).GetAwaiter().GetResult();
        });

        Probe($"{nameof(LegacyTransportPolicy)}.{nameof(LegacyTransportPolicy.ConnectToIndexServerAsync)}", () =>
        {
            using var inner = new MemoryStream();
            using var stream = new SslStream(inner);
            LegacyTransportPolicy.ConnectToIndexServerAsync(stream, PeerHost).GetAwaiter().GetResult();
        });

        Done(nameof(LegacyTransportPolicy));
    }

    private static void SweepAesContentCipher(X509Certificate2 certificate)
    {
        using var content = AesContentCipher.CreateContentCipher(Key);
        using var thumbnail = AesContentCipher.CreateThumbnailCipher(Key);
        using var bulk = AesContentCipher.CreateBulkCipher();
        using var mobile = AesContentCipher.CreateMobileCipher(Key);

        AesContentCipher.TenantEncryptionParameters("basic");
        AesContentCipher.TenantEncryptionParameters("business");
        AesContentCipher.TenantEncryptionParameters("enterprise");
        AesContentCipher.WrapWithAes128(Document);
        AesContentCipher.WrapWithAes256(Document);
        AesContentCipher.EncodeKeyWrapAlgorithm();
        AesContentCipher.ExportModernPfx(certificate, Password);
        AesContentCipher.CreatePluginCipher()?.Dispose();

        Done(nameof(AesContentCipher));
    }

    private static void SweepDigestAndMacServices()
    {
        DigestAndMacServices.ComputeDocumentId(Document);
        DigestAndMacServices.ComputeManifestDigest(Document);
        DigestAndMacServices.ComputeAuditDigest(Document);
        DigestAndMacServices.ResolveTenantFingerprintDigest();
        DigestAndMacServices.ComputeVariableLengthId(Document, length: 16);
        DigestAndMacServices.ComputeVariableLengthKeyMaterial(Document, length: 64);
        DigestAndMacServices.AuthenticateReplicationMessage(Key, Document);
        DigestAndMacServices.AuthenticateWithSha3(Key, Document);
        DigestAndMacServices.AuthenticateTenantMessage(Key, Document);
        DigestAndMacServices.AuthenticateHighAssuranceMessage(Key, Document);
        DigestAndMacServices.ExpandSessionKeys(Key, Salt, Document);
        DigestAndMacServices.HashPassword(Password, Salt);
        DigestAndMacServices.DeriveSubkey(Key, Salt, Document);
        DigestAndMacServices.ComputeConfiguredDigest(Document);
        DigestAndMacServices.ComputeDigestWithConfiguredAlgorithm(Document);
        DigestAndMacServices.ReadSignatureDigest();
        DigestAndMacServices.ReadTruncatedDigestOid();
        DigestAndMacServices.BuildCngDigestName();

        using var uploadDigest = DigestAndMacServices.CreateUploadDigest();
        using var uploadMac = DigestAndMacServices.CreateUploadMac(Key);
        DigestAndMacServices.CreateIndexDigest()?.Dispose();
        DigestAndMacServices.CreateIndexMac()?.Dispose();

        if (OperatingSystem.IsWindows())
        {
            SweepWindowsDigestAndMacServices();
        }

        Done(nameof(DigestAndMacServices));
    }

    [SupportedOSPlatform("windows")]
    private static void SweepWindowsDigestAndMacServices()
    {
        using var signingKey = DigestAndMacServices.ConfigureWindowsSigningKey();
    }

    private static void SweepMlKemKeyExchange(X509Certificate2 certificate)
    {
        using var sessionKey = MlKemKeyExchange.CreateSessionKey();
        using var embedded = MlKemKeyExchange.CreateEmbeddedSessionKey();
        using var highAssurance = MlKemKeyExchange.CreateHighAssuranceSessionKey();
        using var embeddedTier = MlKemKeyExchange.CreateSessionKeyForTier("embedded");
        using var highTier = MlKemKeyExchange.CreateSessionKeyForTier("high");
        using var defaultTier = MlKemKeyExchange.CreateSessionKeyForTier("standard");
        using var imported = MlKemKeyExchange.ImportPeerEncapsulationKey(sessionKey.ExportEncapsulationKey());
        using var fromPem = MlKemKeyExchange.ImportPeerKeyFromPem(sessionKey.ExportSubjectPublicKeyInfoPem());

        MlKemKeyExchange.ReadPeerKemAlgorithm();
        MlKemKeyExchange.ReadHighAssuranceKemAlgorithm();
        MlKemKeyExchange.ReadCertificateKey(certificate)?.Dispose();

        if (OperatingSystem.IsWindows())
        {
            SweepWindowsMlKemKeyExchange();
        }
        else if (!OperatingSystem.IsMacOS())
        {
            SweepOpenSslMlKemKeyExchange();
        }

        Done(nameof(MlKemKeyExchange));
    }

    [SupportedOSPlatform("windows")]
    private static void SweepWindowsMlKemKeyExchange()
    {
        Probe($"{nameof(MlKemKeyExchange)}.{nameof(MlKemKeyExchange.OpenPlatformDecapsulationKey)}", () =>
        {
            using var cngKey = MlKemKeyExchange.OpenPlatformDecapsulationKey();
            using var wrapped = MlKemKeyExchange.OpenPlatformKey(cngKey);
        });
    }

    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("macos")]
    private static void SweepOpenSslMlKemKeyExchange()
    {
        Probe($"{nameof(MlKemKeyExchange)}.{nameof(MlKemKeyExchange.OpenOpenSslKey)}", () =>
        {
            using var rsa = RsaKeyVault.CreateSigningKey();
            using var openSslKey = (RSAOpenSsl)RsaKeyVault.CreateSigningKeyOnLinux(rsa.ExportParameters(true));
            using var handle = openSslKey.DuplicateKeyHandle();
            using var wrapped = MlKemKeyExchange.OpenOpenSslKey(handle);
        });
    }

    private static void SweepMlDsaSigner(X509Certificate2 certificate)
    {
        using var documentKey = MlDsaSigner.CreateDocumentSigningKey();
        using var handshakeKey = MlDsaSigner.CreateHandshakeSigningKey();
        using var rootKey = MlDsaSigner.CreateRootSigningKey();
        using var firmwareKey = MlDsaSigner.CreateFirmwareSigningKey();
        using var secondaryFirmwareKey = MlDsaSigner.CreateSecondaryFirmwareSigningKey();
        using var bootloaderKey = MlDsaSigner.CreateBootloaderSigningKey();
        using var importedRoot = MlDsaSigner.ImportPeerVerificationKey(rootKey.ExportMLDsaPublicKey());
        using var importedSpki = MlDsaSigner.ImportPeerVerificationKeyFromSpki(documentKey.ExportSubjectPublicKeyInfo());
        using var importedFirmware = MlDsaSigner.ImportFirmwareVerificationKey(bootloaderKey.ExportSubjectPublicKeyInfoPem());

        MlDsaSigner.IsFirmwareSigningAvailable();
        MlDsaSigner.ReadSignatureAlgorithm();
        MlDsaSigner.ReadPreHashSignatureAlgorithm();
        MlDsaSigner.ReadFirmwareSignatureAlgorithm();
        MlDsaSigner.CreateIssuingGenerator(documentKey);
        MlDsaSigner.CreateFirmwareIssuingGenerator(firmwareKey);
        MlDsaSigner.ReadCertificateKey(certificate)?.Dispose();

        if (OperatingSystem.IsWindows())
        {
            SweepWindowsMlDsaSigner();
        }
        else if (!OperatingSystem.IsMacOS())
        {
            SweepOpenSslMlDsaSigner();
        }

        Done(nameof(MlDsaSigner));
    }

    [SupportedOSPlatform("windows")]
    private static void SweepWindowsMlDsaSigner()
    {
        Probe($"{nameof(MlDsaSigner)}.{nameof(MlDsaSigner.OpenPlatformSigningKey)}", () =>
        {
            using var cngKey = MlDsaSigner.OpenPlatformSigningKey();
            using var wrapped = MlDsaSigner.OpenPlatformKey(cngKey);
        });
    }

    [UnsupportedOSPlatform("windows")]
    [UnsupportedOSPlatform("macos")]
    private static void SweepOpenSslMlDsaSigner()
    {
        Probe($"{nameof(MlDsaSigner)}.{nameof(MlDsaSigner.OpenFirmwareKeyOnLinux)}", () =>
        {
            using var rsa = RsaKeyVault.CreateSigningKey();
            using var openSslKey = (RSAOpenSsl)RsaKeyVault.CreateSigningKeyOnLinux(rsa.ExportParameters(true));
            using var handle = openSslKey.DuplicateKeyHandle();
            using var wrapped = MlDsaSigner.OpenFirmwareKeyOnLinux(handle);
        });
    }

    private static void SweepHybridCompositeSigner(X509Certificate2 certificate)
    {
        using var handshakeKey = HybridCompositeSigner.CreateTransitionalHandshakeKey();
        using var rsaProfileKey = HybridCompositeSigner.CreateKeyForProfile(preferEdwards: false);

        HybridCompositeSigner.IsTransitionalProfileAvailable();
        HybridCompositeSigner.ReadCertificateKey(certificate)?.Dispose();

        Probe($"{nameof(HybridCompositeSigner)}.{nameof(HybridCompositeSigner.CreateTransitionalRootKey)}",
            () => HybridCompositeSigner.CreateTransitionalRootKey().Dispose());
        Probe($"{nameof(HybridCompositeSigner)}.{nameof(HybridCompositeSigner.CreateBrainpoolPairedKey)}",
            () => HybridCompositeSigner.CreateBrainpoolPairedKey().Dispose());
        Probe($"{nameof(HybridCompositeSigner)}.{nameof(HybridCompositeSigner.CreateKeyForProfile)}(edwards)",
            () => HybridCompositeSigner.CreateKeyForProfile(preferEdwards: true).Dispose());
        Probe($"{nameof(HybridCompositeSigner)}.{nameof(HybridCompositeSigner.CreateIssuingGenerator)}", () =>
        {
            using var caKey = HybridCompositeSigner.CreateTransitionalDocumentKey();
            HybridCompositeSigner.CreateIssuingGenerator(caKey);
        });

        Probe($"{nameof(HybridCompositeSigner)}.{nameof(HybridCompositeSigner.ImportPeerVerificationKey)}", () =>
        {
            using var peerKey = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP521);
            using var imported = HybridCompositeSigner.ImportPeerVerificationKey(peerKey.ExportCompositeMLDsaPublicKey());
        });

        Done(nameof(HybridCompositeSigner));
    }

    private static void Done(string className) => Console.WriteLine($"    {className,-24} all members called");

    /// <summary>
    /// Calls an inventory path that cannot succeed everywhere and reports what happened.
    /// </summary>
    private static void Probe(string label, Action call)
    {
        try
        {
            call();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"      {label,-58} unavailable here ({ex.GetType().Name})");
        }
    }
}
