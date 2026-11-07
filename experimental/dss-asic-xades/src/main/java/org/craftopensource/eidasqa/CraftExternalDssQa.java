package org.craftopensource.eidasqa;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Demonstrates DSS -> raw ToBeSigned -> separate signing process -> DSS ASiC.
 * This QA class supports a disposable PKCS#12 test and one strictly
 * pinned local self-signed Windows CurrentUser/My software certificate.
 * An additional owner-present hardware QA mode, never invoked by automated
 * tests, requires a B-Trust public certificate and a second human Windows
 * confirmation before any provider PIN UI. No qualified validation is implied.
 */
public final class CraftExternalDssQa {
    private static final X500Principal ONLY_ALLOWED_TEST_ID = new X500Principal(
        "CN=Craft Open Source Disposable XAdES QA Only,O=Technical Test");
    private static final X500Principal WINDOWS_LOCAL_TEST_ID = new X500Principal(
        "CN=Craft Open Source Local Code Signing");
    private static final String HELPER_FLAG = "CRAFT_DSS_DISPOSABLE_SOFTWARE_TEST_ONLY_V1";
    private static final String WINDOWS_LOCAL_HELPER_FLAG = "CRAFT_WINDOWS_LOCAL_SELF_SIGNED_QA_V1";
    private static final String BTRUST_OWNER_HELPER_FLAG = "CRAFT_OWNER_PRESENT_BTRUST_HARDWARE_QA_V1";
    private CraftExternalDssQa() {}

    public static void main(String[] args) throws Exception {
        boolean disposable = args.length == 6
            && args[0].equals("--sign-external-test")
            && args[5].equals("--strict-test-only");
        boolean windowsLocal = args.length == 6
            && args[0].equals("--sign-windows-local-test")
            && args[5].equals("--strict-windows-test-only");
        boolean ownerPresentBTrust = args.length == 6
            && args[0].equals("--sign-btrust-owner-qa")
            && args[5].equals("--owner-confirmation-required");
        if (!disposable && !windowsLocal && !ownerPresentBTrust) {
            throw new IllegalArgumentException(
                "Supported: disposable QA, local Windows QA, or explicitly owner-confirmed B-Trust QA");
        }
        Path source = Path.of(args[1]).toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path destination = Path.of(args[2]).toAbsolutePath().normalize();
        Path publicCert = Path.of(args[3]).toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path testP12 = disposable
            ? Path.of(args[4]).toRealPath(LinkOption.NOFOLLOW_LINKS) : null;
        String windowsThumbprint = (windowsLocal || ownerPresentBTrust)
            ? args[4].toUpperCase(Locale.ROOT) : null;
        if ((windowsLocal || ownerPresentBTrust)
                && !windowsThumbprint.matches("[0-9A-F]{40}")) {
            throw new IllegalArgumentException("Exactly one 40-hex selected certificate thumbprint required");
        }

        String name = source.getFileName().toString().toLowerCase(Locale.ROOT);
        if (!(name.endsWith(".docx") || name.endsWith(".xlsx"))
                || !Files.isRegularFile(source)
                || (disposable && (!Files.isRegularFile(testP12)
                    || !testP12.toString().endsWith(".p12")))
                || !Files.isRegularFile(publicCert)
                || Files.size(source) > (64L * 1024 * 1024)
                || Files.exists(destination)
                || !destination.toString().toLowerCase(Locale.ROOT).endsWith(".asics")) {
            throw new IllegalArgumentException("Refused source, keys, or output; test only, new .asics required");
        }
        Path parent = destination.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IllegalArgumentException("Parent output directory unavailable");
        }
        // The separate helper, not DSS, owns the private PKCS#12 key.
        String dotnetRoot = System.getenv("DSS_QA_DOTNET_HOST");
        String helperDll = System.getenv("DSS_QA_SIDECAR_DLL");
        if (dotnetRoot == null || helperDll == null
                || !Path.of(dotnetRoot).getFileName().toString().equalsIgnoreCase("dotnet.exe")
                || !Path.of(helperDll).getFileName().toString().equals("CraftDisposableSigner.dll")) {
            throw new SecurityException("Dedicated local test signer not explicitly configured");
        }
        Path dotnet = Path.of(dotnetRoot).toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path signer = Path.of(helperDll).toRealPath(LinkOption.NOFOLLOW_LINKS);
        // Deliberately do NOT read DSS_QA_PKCS12_PASSWORD in Java.
        // Only the isolated helper sees this environment variable.
        X509Certificate certificate;
        try (FileInputStream stream = new FileInputStream(publicCert.toFile())) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(stream);
        }
        certificate.checkValidity();
        if (ownerPresentBTrust) {
            // This is NOT invoked by automated tests and may only be run with
            // the owner physically confirming the Windows MessageBox + provider PIN.
            String issuer = certificate.getIssuerX500Principal().getName().toLowerCase(Locale.ROOT);
            if (!source.getFileName().toString().equals("QES_QA_UNSIGNED_ORIGINAL.docx")
                    && !source.getFileName().toString().equals("QES_QA_UNSIGNED_ORIGINAL.xlsx")) {
                throw new SecurityException("Owner-present hardware signing accepts anonymous QA fixtures ONLY");
            }
            if (!issuer.contains("b-trust") || !issuer.contains("operational qualified ca")
                    || certificate.getSubjectX500Principal()
                        .equals(certificate.getIssuerX500Principal())
                    || certificate.getExtensionValue("1.3.6.1.5.5.7.1.3") == null) {
                throw new SecurityException("B-Trust qualified public certificate preflight refused");
            }
        } else {
            X500Principal expectedTestIdentity = windowsLocal
                ? WINDOWS_LOCAL_TEST_ID : ONLY_ALLOWED_TEST_ID;
            if (!certificate.getSubjectX500Principal().equals(expectedTestIdentity)
                    || !certificate.getIssuerX500Principal().equals(expectedTestIdentity)) {
                throw new SecurityException("Real certificates are forbidden in software QA modes");
            }
            certificate.verify(certificate.getPublicKey());
        }
        if (!"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
            throw new SecurityException("Only explicitly selected RSA certificates supported");
        }

        byte[] originalSha256 = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(source));
        byte[] certSha256 = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        String certHash = HexFormat.of().formatHex(certSha256);
        CertificateToken publicToken = new CertificateToken(certificate);

        ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(publicToken);
        parameters.setCertificateChain(List.of(publicToken));

        DSSDocument document = new FileDocument(source.toFile());
        ASiCWithXAdESService service = new ASiCWithXAdESService(new CommonCertificateVerifier());
        ToBeSigned data = service.getDataToSign(document, parameters);
        if (data == null || data.getBytes().length < 16) {
            throw new SecurityException("Empty DSS ToBeSigned data");
        }

        Path session = Files.createTempDirectory(parent, ".craft-dss-qa-external-");
        try {
            Path payload = session.resolve("signedinfo.bin");
            Path signatureOut = session.resolve("signature.bin");
            Files.write(payload, data.getBytes());

            ProcessBuilder command = ownerPresentBTrust
                ? new ProcessBuilder(
                    dotnet.toString(), signer.toString(), "--sign-btrust-owner-qa",
                    windowsThumbprint, payload.toString(), signatureOut.toString(),
                    certHash, source.toString(),
                    HexFormat.of().formatHex(originalSha256), BTRUST_OWNER_HELPER_FLAG)
                : windowsLocal
                    ? new ProcessBuilder(
                        dotnet.toString(), signer.toString(), "--sign-windows-local-test",
                        windowsThumbprint, payload.toString(), signatureOut.toString(),
                        certHash, WINDOWS_LOCAL_HELPER_FLAG)
                    : new ProcessBuilder(
                        dotnet.toString(), signer.toString(), "--sign-disposable",
                        testP12.toString(), payload.toString(), signatureOut.toString(),
                        certHash, HELPER_FLAG);
            command.directory(session.toFile());
            command.redirectErrorStream(true);
            command.redirectOutput(session.resolve("helper-output.log").toFile());
            // The B-Trust mode requires a real owner-present confirmation;
            // only the selected native Windows provider is allowed to request PIN.
            Process process = command.start();
            if (!process.waitFor(ownerPresentBTrust ? 200 : 45, TimeUnit.SECONDS)) {
                process.descendants().forEach(ProcessHandle::destroyForcibly);
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
                throw new SecurityException("External test signer timed out");
            }
            if (process.exitValue() != 0 || !Files.isRegularFile(signatureOut)) {
                throw new SecurityException("External test signing process refused or failed");
            }
            byte[] result = Files.readAllBytes(signatureOut);
            Signature publicCheck = Signature.getInstance("SHA256withRSA");
            publicCheck.initVerify(certificate.getPublicKey());
            publicCheck.update(data.getBytes());
            if (!publicCheck.verify(result)) {
                throw new SecurityException("Detached signature value does not verify against selected public key");
            }
            SignatureValue value = new SignatureValue(SignatureAlgorithm.RSA_SHA256, result);
            DSSDocument completed = service.signDocument(document, parameters, value);
            Path stage = Files.createTempFile(session, "signed", ".asics");
            completed.save(stage.toString());
            // Do not publish an ASiC that DSS cannot independently validate.
            CraftDssBridge.main(new String[]{"--validate", stage.toString()});
            byte[] afterSha256 = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(source));
            if (!MessageDigest.isEqual(originalSha256, afterSha256)) {
                throw new SecurityException("Original source changed during signing");
            }
            // File hardlink publication is atomic and cannot overwrite existing destination.
            Files.createLink(destination, stage);
            System.out.println("EXTERNAL_XADES_SIGNING_BRIDGE_QA_PASS");
            System.out.println("EXTERNAL_KEY_USED_BY_DSS=false");
            System.out.println("EXTERNAL_PROVIDER=" + (ownerPresentBTrust
                ? "OWNER_PRESENT_BTRUST_QA_NOT_QUALIFIED_VALIDATED"
                : windowsLocal
                    ? "WINDOWS_USER_STORE_LOCAL_SELF_SIGNED_TEST"
                    : "DISPOSABLE_PKCS12_SOFTWARE_TEST"));
            System.out.println("TEST_ONLY_NOT_BTRUST_NOT_QES=true");
        } finally {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(session)) {
                for (Path file : ds) {
                    if (Files.isRegularFile(file)) Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(session);
        }
    }
}
