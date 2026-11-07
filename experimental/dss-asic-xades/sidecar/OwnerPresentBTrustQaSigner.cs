using System;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CraftOpenSource.Qa;

/// <summary>
/// NOT production code: owner-present B-Trust hardware QA only.
/// NEVER auto-run. A visible Windows confirmation and provider-owned PIN dialog
/// are mandatory, and the signer refuses all non-anonymous source documents.
/// An authentic signed document is NOT automatically qualified under eIDAS.
/// </summary>
internal static class OwnerPresentBTrustQaSigner
{
    private const string OwnerGate = "CRAFT_OWNER_PRESENT_BTRUST_HARDWARE_QA_V1";
    private const string QcpNaturalQscdPolicyOid = "0.4.0.194112.1.2";
    private const string QcStatementsExtensionOid = "1.3.6.1.5.5.7.1.3";

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBoxW(
        nint hwnd, string text, string caption, uint type);

    // This public-only preflight intentionally does not call GetRSAPrivateKey,
    // sign any data, display a PIN prompt, or return personal certificate IDs.
    public static int PublicPreflight()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        int publicCandidates = 0;
        int policyCandidates = 0;
        int trustedChains = 0;
        foreach (X509Certificate2 cert in store.Certificates)
        {
            if (!cert.Issuer.Contains("B-Trust", StringComparison.OrdinalIgnoreCase)
                || !cert.Issuer.Contains("Operational Qualified CA", StringComparison.OrdinalIgnoreCase)
                || cert.Subject == cert.Issuer)
            {
                continue;
            }
            publicCandidates++;
            if (cert.NotBefore.ToUniversalTime() > DateTime.UtcNow
                || cert.NotAfter.ToUniversalTime() < DateTime.UtcNow
                || cert.Extensions[QcStatementsExtensionOid] is null
                || !HasCertificatePolicy(cert, QcpNaturalQscdPolicyOid))
            {
                continue;
            }
            policyCandidates++;
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
            if (chain.Build(cert))
            {
                trustedChains++;
            }
        }
        Console.WriteLine("BTRUST_PUBLIC_CERTIFICATE_CANDIDATES=" + publicCandidates);
        Console.WriteLine("BTRUST_QCP_N_QSCD_POLICY_MATCHES=" + policyCandidates);
        Console.WriteLine("BTRUST_WINDOWS_CHAIN_ONLINE_PASS=" + trustedChains);
        Console.WriteLine("BTRUST_PUBLIC_PREFLIGHT_NO_PRIVATE_KEY_OPERATION=true");
        return publicCandidates > 0 && policyCandidates == publicCandidates
            && trustedChains == policyCandidates ? 0 : 2;
    }

    public static int Run(string[] args)
    {
        if (args.Length != 8 || args[0] != "--sign-btrust-owner-qa"
            || args[7] != OwnerGate)
        {
            Console.Error.WriteLine("REFUSED: explicit owner-present B-Trust QA gate missing");
            return 64;
        }
        if (!OperatingSystem.IsWindows() || !Environment.UserInteractive)
        {
            Console.Error.WriteLine("REFUSED: owner must be on an interactive Windows desktop");
            return 65;
        }
        string thumbprint = args[1].Replace(" ", string.Empty, StringComparison.Ordinal)
            .ToUpperInvariant();
        string tbsPath = Path.GetFullPath(args[2]);
        string signaturePath = Path.GetFullPath(args[3]);
        string expectedCertSha256 = args[4];
        string sourcePath = Path.GetFullPath(args[5]);
        string sourceSha256 = args[6];
        string filename = Path.GetFileName(sourcePath);
        if (thumbprint.Length != 40 || !thumbprint.All(Uri.IsHexDigit)
            || expectedCertSha256.Length != 64 || !expectedCertSha256.All(Uri.IsHexDigit)
            || sourceSha256.Length != 64 || !sourceSha256.All(Uri.IsHexDigit)
            || (filename != "QES_QA_UNSIGNED_ORIGINAL.docx"
                && filename != "QES_QA_UNSIGNED_ORIGINAL.xlsx")
            || !File.Exists(sourcePath) || !File.Exists(tbsPath)
            || File.Exists(signaturePath) || Directory.Exists(signaturePath)
            || signaturePath.Equals(tbsPath, StringComparison.OrdinalIgnoreCase)
            || signaturePath.Equals(sourcePath, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("REFUSED: must sign only a new output for a preapproved anonymous QA file");
            return 66;
        }
        byte[] sourceHashBefore = SHA256.HashData(File.ReadAllBytes(sourcePath));
        if (!CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(sourceSha256), sourceHashBefore))
        {
            Console.Error.WriteLine("REFUSED: source changed between DSS preparation and provider call");
            return 67;
        }

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection matches = store.Certificates.Find(
            X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        if (matches.Count != 1)
        {
            Console.Error.WriteLine("REFUSED: selected B-Trust certificate missing or ambiguous");
            return 68;
        }
        using X509Certificate2 cert = matches[0];
        string issuer = cert.Issuer;
        if (!issuer.Contains("B-Trust", StringComparison.OrdinalIgnoreCase)
            || !issuer.Contains("Operational Qualified CA", StringComparison.OrdinalIgnoreCase)
            || cert.Subject == cert.Issuer
            || !cert.HasPrivateKey
            || cert.NotBefore.ToUniversalTime() > DateTime.UtcNow
            || cert.NotAfter.ToUniversalTime() < DateTime.UtcNow
            || cert.Extensions[QcStatementsExtensionOid] is null
            || !HasCertificatePolicy(cert, QcpNaturalQscdPolicyOid))
        {
            Console.Error.WriteLine("REFUSED: certificate lacks required B-Trust QCP-n-qscd public policy");
            return 69;
        }
        if (!CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(cert.RawData), Convert.FromHexString(expectedCertSha256)))
        {
            Console.Error.WriteLine("REFUSED: user-selected B-Trust certificate is not the DSS public certificate");
            return 70;
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        if (!chain.Build(cert))
        {
            Console.Error.WriteLine("REFUSED: Windows certificate chain or online revocation check failed");
            return 71;
        }

        byte[] signedInfo = File.ReadAllBytes(tbsPath);
        if (signedInfo.Length < 16 || signedInfo.Length > 8 * 1024 * 1024)
        {
            Console.Error.WriteLine("REFUSED: invalid XAdES SignedInfo size");
            return 72;
        }
        string text =
            "ТЕСТОВО ПОДПИСВАНЕ С КЕП B-Trust\n\n" +
            "Файл: " + filename + "\n" +
            "Сертификат: " + cert.GetNameInfo(X509NameType.SimpleName, false) + "\n\n" +
            "Продължаване ще извика Windows доставчика и може да поиска ПИН. " +
            "Подписът ще бъде реален, макар документът да е тестов. " +
            "Потвърдете само ако сте лично пред Lenovo.\n\n" +
            "Желаете ли да продължите?";
        const uint MB_YESNO = 0x00000004;
        const uint MB_ICONWARNING = 0x00000030;
        const uint MB_DEFBUTTON2 = 0x00000100;
        const uint MB_TOPMOST = 0x00040000;
        int answer = MessageBoxW(0, text,
            "Craft QES: изрично потвърждение от притежателя",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST);
        if (answer != 6)
        {
            Console.Error.WriteLine("REFUSED: owner declined the hardware QA signing action");
            return 73;
        }

        // Do not acquire the private key until AFTER explicit human approval.
        // The Windows CNG/CSP/B-Trust provider is responsible for any native PIN UI.
        using RSA? rsa = cert.GetRSAPrivateKey();
        if (rsa is null || rsa.KeySize < 2048)
        {
            Console.Error.WriteLine("REFUSED: provider declined or unsupported RSA key");
            return 74;
        }
        byte[] signature = rsa.SignData(
            signedInfo, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using RSA? verifier = cert.GetRSAPublicKey();
        if (verifier is null || !verifier.VerifyData(
            signedInfo, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            Console.Error.WriteLine("REFUSED: provider signature not verified with selected public key");
            return 75;
        }
        byte[] afterHash = SHA256.HashData(File.ReadAllBytes(sourcePath));
        if (!CryptographicOperations.FixedTimeEquals(sourceHashBefore, afterHash))
        {
            Console.Error.WriteLine("REFUSED: source changed during provider interaction");
            return 76;
        }
        using (FileStream output = new(
            signaturePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(signature);
            output.Flush(flushToDisk: true);
        }
        CryptographicOperations.ZeroMemory(signedInfo);
        Console.WriteLine("BTRUST_OWNER_PRESENT_HARDWARE_SIGNATURE_BYTES_CREATED");
        Console.WriteLine("BTRUST_EIDAS_QUALIFICATION_NOT_YET_VALIDATED");
        return 0;
    }

    private static bool HasCertificatePolicy(X509Certificate2 cert, string policyOid)
    {
        X509Extension? extension = cert.Extensions["2.5.29.32"];
        if (extension is null) return false;
        try
        {
            var outer = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            AsnReader policies = outer.ReadSequence();
            while (policies.HasData)
            {
                AsnReader info = policies.ReadSequence();
                string oid = info.ReadObjectIdentifier();
                if (oid == policyOid) return true;
            }
        }
        catch (AsnContentException)
        {
            return false;
        }
        return false;
    }
}
