package org.craftopensource.eidasqa;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.simplereport.SimpleReport;
import java.security.KeyStore;
import java.util.Arrays;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.nio.charset.StandardCharsets;
import java.io.InputStream;
import javax.security.auth.x500.X500Principal;

/**
 * Isolated EU DSS 6.5.1 ASiC-S/XAdES Baseline-B proof-of-concept.
 *
 * This intentionally never opens Windows certificate storage: it accepts
 * only a disposable, self-issued test PKCS#12 subject, via environment password.
 * Structure checking is NOT eIDAS qualified-signature validation.
 */
public final class CraftDssBridge {
    private CraftDssBridge() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--self-test")) {
            System.out.println("DSS_QA_BOOTSTRAP_OK expected_version=6.5.1");
            return;
        }
        if (args.length == 2 && args[0].equals("--inspect")) {
            inspect(Path.of(args[1]));
            return;
        }
        if (args.length == 2 && args[0].equals("--validate")) {
            validate(Path.of(args[1]));
            return;
        }
        if (args.length != 5 || !args[0].equals("--sign-software-test")
                || !args[4].equals("--disposable-pkcs12-test-only")) {
            throw new IllegalArgumentException(
                "Use --self-test, --inspect <asics>, or --sign-software-test <source.docx|xlsx> <new.asics> <disposable.p12> --disposable-pkcs12-test-only");
        }
        Path source = Path.of(args[1]).toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path destination = Path.of(args[2]).toAbsolutePath().normalize();
        Path temporaryPkcs12 = Path.of(args[3]).toRealPath(LinkOption.NOFOLLOW_LINKS);
        if (!Files.isRegularFile(temporaryPkcs12)
                || !temporaryPkcs12.toString().toLowerCase(Locale.ROOT).endsWith(".p12")) {
            throw new IllegalArgumentException("Use a disposable PKCS#12 file only");
        }
        String passwordString = System.getenv("DSS_QA_PKCS12_PASSWORD");
        if (passwordString == null || passwordString.length() < 20) {
            throw new SecurityException("DSS_QA_PKCS12_PASSWORD environment variable is required");
        }
        char[] password = passwordString.toCharArray();
        String fileName = source.getFileName().toString().toLowerCase(Locale.ROOT);
        if (!(fileName.endsWith(".docx") || fileName.endsWith(".xlsx"))) {
            throw new IllegalArgumentException("Only DOCX or XLSX source files are accepted");
        }
        if (!Files.isRegularFile(source) || Files.exists(destination)) {
            throw new IllegalArgumentException("Source must exist and destination must be new");
        }
        if (!destination.toString().toLowerCase(Locale.ROOT).endsWith(".asics")) {
            throw new IllegalArgumentException("Output must end with .asics");
        }
        Path folder = destination.getParent();
        if (!Files.isDirectory(folder)) {
            throw new IllegalArgumentException("Output folder missing");
        }

        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                    temporaryPkcs12.toFile(), new KeyStore.PasswordProtection(password))) {
            List<DSSPrivateKeyEntry> candidates = token.getKeys();
            if (candidates.size() != 1) {
                throw new SecurityException("Disposable PKCS#12 must contain exactly one key");
            }
            DSSPrivateKeyEntry key = candidates.get(0);
            X509Certificate cert = key.getCertificate().getCertificate();
            X500Principal subject = cert.getSubjectX500Principal();
            X500Principal issuer = cert.getIssuerX500Principal();
            if (!subject.equals(issuer)
                    || !subject.getName(X500Principal.RFC2253)
                        .contains("CN=Craft Open Source Disposable XAdES QA Only")) {
                throw new SecurityException(
                    "This tool forbids all hardware, B-Trust, and non-disposable certificates");
            }

            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(key.getCertificate());
            parameters.setCertificateChain(key.getCertificateChain());

            DSSDocument document = new FileDocument(source.toFile());
            ASiCWithXAdESService service =
                new ASiCWithXAdESService(new CommonCertificateVerifier());
            ToBeSigned dataToSign = service.getDataToSign(document, parameters);
            SignatureValue signature = token.sign(dataToSign, parameters.getDigestAlgorithm(), key);
            DSSDocument signed = service.signDocument(document, parameters, signature);

            Path staging = Files.createTempFile(folder, ".craft-dss-qa-", ".tmp");
            try {
                signed.save(staging.toString());
                inspect(staging);
                // NTFS hard-link publication is atomic and refuses an existing output.
                Files.createLink(destination, staging);
                System.out.println("DSS_XADES_ASICS_SOFTWARE_QA_CREATED");
            } finally {
                Files.deleteIfExists(staging);
            }
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void validate(Path candidate) throws Exception {
        Path source = candidate.toRealPath(LinkOption.NOFOLLOW_LINKS);
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
            new FileDocument(source.toFile()));
        if (validator == null) throw new IllegalArgumentException("Not a signed DSS-supported document");
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        DiagnosticData diagnostics = reports.getDiagnosticData();
        SimpleReport simple = reports.getSimpleReport();
        List<String> ids = diagnostics.getSignatureIdList();
        if (ids.size() != 1) {
            throw new IllegalArgumentException("Expected one XAdES QA signature; found " + ids.size());
        }
        String id = ids.get(0);
        SignatureWrapper signature = diagnostics.getSignatureById(id);
        if (signature == null) throw new IllegalArgumentException("Signature diagnostics missing");
        boolean intact = signature.isSignatureIntact();
        boolean valid = signature.isSignatureValid();
        System.out.println("DSS_CRYPTOGRAPHIC_SIGNATURE_INTACT=" + intact);
        System.out.println("DSS_CRYPTOGRAPHIC_ALL_SIGNED_DATA_VALID=" + valid);
        System.out.println("DSS_SIGNATURE_LEVEL=" + simple.getSignatureFormat(id));
        System.out.println("DSS_ETSI_INDICATION=" + simple.getIndication(id));
        System.out.println("DSS_SIGNATURE_QUALIFICATION=" + simple.getSignatureQualification(id));
        System.out.println("DSS_QA_NOTICE=self-signed-software-certificate-not-QES");
        if (!intact || !valid) {
            throw new IllegalArgumentException("DSS cryptographic signature or signed-data digest FAILED");
        }
    }

    private static void inspect(Path candidate) throws Exception {
        try (ZipFile zip = new ZipFile(candidate.toFile())) {
            ZipEntry entry = zip.getEntry("META-INF/signatures.xml");
            if (entry == null) {
                throw new IllegalArgumentException("XAdES signatures.xml entry absent");
            }
            String text;
            try (InputStream stream = zip.getInputStream(entry)) {
                text = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            }
            if (!text.contains("QualifyingProperties")
                || !text.contains("http://uri.etsi.org/01903")
                || !text.contains("SignedProperties")) {
                throw new IllegalArgumentException("Signature is missing signed XAdES attributes");
            }
            if (zip.getEntry("mimetype") == null) {
                throw new IllegalArgumentException("ASiC mimetype entry absent");
            }
            System.out.println("DSS_XADES_ASICS_STRUCTURE_OK only_structure_not_crypto_or_QES");
        }
    }
}
