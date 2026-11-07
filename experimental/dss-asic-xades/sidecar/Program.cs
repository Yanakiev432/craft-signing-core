using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CraftOpenSource.Qa;

internal static class Program
{
    private const string AllowedCommonName = "CN=Craft Open Source Disposable XAdES QA Only";
    private const string ExpectedLabel = "CRAFT_DSS_DISPOSABLE_SOFTWARE_TEST_ONLY_V1";

    public static int Main(string[] args)
    {
        try
        {
            // A second, strictly local test mode exercises the actual Windows
            // CurrentUser/My CNG/CSP provider without selecting any real user cert.
            if (args.Length == 6 && args[0] == "--sign-windows-local-test")
            {
                return SignWindowsLocalTest(args);
            }
            if (args.Length == 8 && args[0] == "--sign-btrust-owner-qa")
            {
                // No automatic B-Trust key operation; owner must approve Windows UI.
                return OwnerPresentBTrustQaSigner.Run(args);
            }
            if (args.Length == 1 && args[0] == "--btrust-public-preflight")
            {
                return OwnerPresentBTrustQaSigner.PublicPreflight();
            }
            if (args.Length != 6 || args[0] != "--sign-disposable"
                || args[5] != ExpectedLabel)
            {
                Console.Error.WriteLine("REFUSED: six exact arguments required; disposable software test ONLY");
                return 64;
            }

            string keyPath = Path.GetFullPath(args[1]);
            string toBeSignedPath = Path.GetFullPath(args[2]);
            string signaturePath = Path.GetFullPath(args[3]);
            string expectedCertificateSha256 = args[4];
            if (!keyPath.EndsWith(".p12", StringComparison.OrdinalIgnoreCase)
                || !File.Exists(keyPath)
                || !File.Exists(toBeSignedPath)
                || !expectedCertificateSha256.All(Uri.IsHexDigit)
                || expectedCertificateSha256.Length != 64)
            {
                Console.Error.WriteLine("REFUSED: invalid test keystore or fingerprint");
                return 65;
            }
            if (File.Exists(signaturePath) || Directory.Exists(signaturePath)
                || Path.GetFullPath(signaturePath).Equals(keyPath, StringComparison.OrdinalIgnoreCase)
                || Path.GetFullPath(signaturePath).Equals(toBeSignedPath, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("REFUSED: must create a new separate signature output");
                return 66;
            }
            string? password = Environment.GetEnvironmentVariable("DSS_QA_PKCS12_PASSWORD");
            if (string.IsNullOrWhiteSpace(password) || password.Length < 20)
            {
                Console.Error.WriteLine("REFUSED: disposable test passphrase not supplied");
                return 67;
            }
            // EphemeralKeySet: no persistent key in Windows certificate/user stores.
            using var certificate = new X509Certificate2(
                keyPath, password,
                X509KeyStorageFlags.EphemeralKeySet);
            if (!certificate.HasPrivateKey
                || !certificate.Subject.Contains(AllowedCommonName, StringComparison.Ordinal)
                || certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData) == false)
            {
                Console.Error.WriteLine("REFUSED: this tool cannot use B-Trust, real or CA-issued certificates");
                return 68;
            }

            byte[] actualCertificateDigest = SHA256.HashData(certificate.RawData);
            byte[] expectedDigest = Convert.FromHexString(expectedCertificateSha256);
            if (!CryptographicOperations.FixedTimeEquals(actualCertificateDigest, expectedDigest))
            {
                Console.Error.WriteLine("REFUSED: certificate mismatch between Java DSS and signer");
                return 69;
            }
            byte[] data = File.ReadAllBytes(toBeSignedPath);
            if (data.Length < 16 || data.Length > 8 * 1024 * 1024)
            {
                Console.Error.WriteLine("REFUSED: unexpected SignedInfo length");
                return 70;
            }
            using RSA? rsa = certificate.GetRSAPrivateKey();
            if (rsa is null || rsa.KeySize < 2048)
            {
                Console.Error.WriteLine("REFUSED: RSA key not usable");
                return 71;
            }
            byte[] signature = rsa.SignData(
                data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using (FileStream stream = new(
                signaturePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(signature);
                stream.Flush(flushToDisk: true);
            }
            CryptographicOperations.ZeroMemory(data);
            Console.WriteLine("EXTERNAL_DISPOSABLE_RSA_SHA256_SIGN_OK");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(
                "REFUSED: " + exception.GetType().Name);
            return 1;
        }
    }

    private static int SignWindowsLocalTest(string[] args)
    {
        // This test mode cannot select B-Trust certificates, nor arbitrary
        // certificates in the Windows store, even with a valid thumbprint.
        const string exactSubject = "CN=Craft Open Source Local Code Signing";
        const string gate = "CRAFT_WINDOWS_LOCAL_SELF_SIGNED_QA_V1";
        if (args.Length != 6 || args[5] != gate)
        {
            Console.Error.WriteLine("REFUSED: local Windows test gate missing");
            return 64;
        }
        string selector = args[1].Replace(" ", string.Empty, StringComparison.Ordinal);
        if (selector.Length != 40 || !selector.All(Uri.IsHexDigit))
        {
            Console.Error.WriteLine("REFUSED: explicit test certificate thumbprint required");
            return 65;
        }
        string toBeSignedPath = Path.GetFullPath(args[2]);
        string signaturePath = Path.GetFullPath(args[3]);
        string expectedCertSha256 = args[4];
        if (!File.Exists(toBeSignedPath)
            || expectedCertSha256.Length != 64
            || !expectedCertSha256.All(Uri.IsHexDigit)
            || File.Exists(signaturePath) || Directory.Exists(signaturePath)
            || signaturePath.Equals(toBeSignedPath, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("REFUSED: file or fingerprint validation failed");
            return 66;
        }
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint, selector, validOnly: false);
        if (matches.Count != 1)
        {
            Console.Error.WriteLine("REFUSED: Windows local software certificate not uniquely found");
            return 67;
        }
        using var certificate = matches[0];
        if (certificate.Subject != exactSubject
            || certificate.Issuer != exactSubject
            || !certificate.HasPrivateKey
            || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow
            || certificate.NotAfter.ToUniversalTime() < DateTime.UtcNow)
        {
            Console.Error.WriteLine("REFUSED: selected certificate is not the sole permitted local test identity");
            return 68;
        }
        byte[] expected = Convert.FromHexString(expectedCertSha256);
        byte[] actual = SHA256.HashData(certificate.RawData);
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            Console.Error.WriteLine("REFUSED: Windows certificate does not match DSS public identity");
            return 69;
        }
        byte[] data = File.ReadAllBytes(toBeSignedPath);
        if (data.Length < 16 || data.Length > 8 * 1024 * 1024)
        {
            Console.Error.WriteLine("REFUSED: SignedInfo size invalid");
            return 70;
        }
        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is null || rsa.KeySize < 2048)
        {
            Console.Error.WriteLine("REFUSED: Windows RSA signing key unavailable");
            return 71;
        }
        byte[] signature = rsa.SignData(
            data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using (FileStream output = new(
            signaturePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(signature);
            output.Flush(flushToDisk: true);
        }
        CryptographicOperations.ZeroMemory(data);
        Console.WriteLine("WINDOWS_STORE_LOCAL_QA_RSA_SHA256_SIGN_OK");
        return 0;
    }
}
