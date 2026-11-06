// Block 15 - D3/D4b: a TEST Chimera hierarchy whose keys we control, standing for an adversary that
// can forge the classical (RSA) signature of a Chimera CA. Every leaf has a VALID classical signature;
// only its alternative (ML-DSA) part differs. Private keys exist only in memory and are never written.
//   root  RSA-4096 + ML-DSA-87 (alt),  sub  RSA-4096 + ML-DSA-65 (alt),  leaves EC P-256
//   L0-chimera-ok            control: classical + alternative signature
//   L1-classic-under-chimera classical signature only, no alternative extensions        (D3, downgrade)
//   L2c-rebuilt-unchanged    control: L0 rebuilt and classically re-signed, unchanged   (checks the rebuild)
//   L2-altsig-byte-flipped   L0 with one byte of altSignatureValue flipped, re-signed   (D4b)
//   L3-altsig-removed        L0 without altSignatureValue (altSignatureAlgorithm kept), re-signed (D4b)
//   L4-altsig-wrong-key      alternative signature made with another ML-DSA-65 key      (D4b)
// Usage: java -cp <bcprov>:<bcpkix>:<bcutil>:. Forge15 <output dir>
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Forge15 {
    static final String BC = "BC";
    static long serial = 0x15000000L;
    static String dir;

    static KeyPair gen(String alg, Object spec) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(alg, BC);
        if (spec instanceof Integer) g.initialize((Integer) spec);
        else if (spec != null) g.initialize((java.security.spec.AlgorithmParameterSpec) spec);
        return g.generateKeyPair();
    }
    static ContentSigner signer(String alg, PrivateKey k) throws Exception {
        return new JcaContentSignerBuilder(alg).setProvider(BC).build(k);
    }
    static X509v3CertificateBuilder builder(String issuer, String subject, PublicKey pub, boolean ca, PublicKey altPub) throws Exception {
        Date nb = new Date(System.currentTimeMillis() - 3600_000L), na = new Date(System.currentTimeMillis() + 365L * 86400_000L);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(serial++), nb, na, new X500Name(subject), pub);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (!ca) b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}));
        if (altPub != null) b.addExtension(Extension.subjectAltPublicKeyInfo, false, SubjectAltPublicKeyInfo.getInstance(altPub.getEncoded()));
        return b;
    }
    // Copy of a certificate field by field and extension by extension, in the same order (the BC template
    // constructor drops the alternative-signature extensions). mode: keep | flip (altSignatureValue) | drop
    static X509v3CertificateBuilder copy(X509CertificateHolder c, String mode) throws Exception {
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(c.getIssuer(), c.getSerialNumber(), c.getNotBefore(), c.getNotAfter(),
                c.getSubject(), c.getSubjectPublicKeyInfo());
        for (ASN1ObjectIdentifier oid : c.getExtensions().getExtensionOIDs()) {
            Extension e = c.getExtension(oid);
            if (oid.equals(Extension.altSignatureValue)) {
                if (mode.equals("drop")) continue;
                if (mode.equals("flip")) {
                    byte[] v = AltSignatureValue.getInstance(e.getParsedValue()).getSignature().getBytes();
                    v[v.length / 2] ^= 0x01;
                    b.addExtension(oid, e.isCritical(), new AltSignatureValue(v));
                    continue;
                }
            }
            b.addExtension(e);
        }
        return b;
    }
    static void write(String name, X509CertificateHolder h, String what) throws Exception {
        try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(dir + "/" + name + ".crt"))) { w.writeObject(h); }
        System.out.printf("%-26s %5d B DER  %s%n", name, h.getEncoded().length, what);
    }

    public static void main(String[] a) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        dir = a[0];
        KeyPair rootK = gen("RSA", 4096), rootAlt = gen("ML-DSA-87", null);
        KeyPair subK = gen("RSA", 4096), subAlt = gen("ML-DSA-65", null), wrongAlt = gen("ML-DSA-65", null);
        String R = "CN=TFM15 Forged Root CA Hybrid,O=UPV-TFM test,C=ES", S = "CN=TFM15 Forged Sub CA Hybrid,O=UPV-TFM test,C=ES";

        X509CertificateHolder root = builder(R, R, rootK.getPublic(), true, rootAlt.getPublic())
                .build(signer("SHA256withRSA", rootK.getPrivate()), false, signer("ML-DSA-87", rootAlt.getPrivate()));
        X509CertificateHolder sub = builder(R, S, subK.getPublic(), true, subAlt.getPublic())
                .build(signer("SHA256withRSA", rootK.getPrivate()), false, signer("ML-DSA-87", rootAlt.getPrivate()));
        write("forged-root", root, "test root (RSA-4096 + ML-DSA-87)");
        write("forged-sub", sub, "test sub CA (RSA-4096 + ML-DSA-65)");
        try (JcaPEMWriter w = new JcaPEMWriter(new FileWriter(dir + "/forged-bundle.crt"))) { w.writeObject(sub); w.writeObject(root); }

        ContentSigner cls = signer("SHA256withRSA", subK.getPrivate());
        KeyPair leafK = gen("EC", new ECGenParameterSpec("P-256"));
        X509CertificateHolder l0 = builder(S, "CN=L0-chimera-ok,O=UPV-TFM test,C=ES", leafK.getPublic(), false, null)
                .build(cls, false, signer("ML-DSA-65", subAlt.getPrivate()));
        write("L0-chimera-ok", l0, "control: classical + alternative signature");
        write("L1-classic-under-chimera", builder(S, "CN=L1-classic-under-chimera,O=UPV-TFM test,C=ES", leafK.getPublic(), false, null)
                .build(signer("SHA256withRSA", subK.getPrivate())), "classical signature only (no alternative extensions)");
        // L2c/L2/L3: L0 copied field by field and extension by extension, then classically re-signed
        write("L2c-rebuilt-unchanged", copy(l0, "keep").build(signer("SHA256withRSA", subK.getPrivate())),
                "control: L0 rebuilt and re-signed, nothing changed");
        write("L2-altsig-byte-flipped", copy(l0, "flip").build(signer("SHA256withRSA", subK.getPrivate())),
                "one byte of altSignatureValue flipped, re-signed");
        write("L3-altsig-removed", copy(l0, "drop").build(signer("SHA256withRSA", subK.getPrivate())),
                "altSignatureValue removed (altSignatureAlgorithm kept), re-signed");
        write("L4-altsig-wrong-key", builder(S, "CN=L4-altsig-wrong-key,O=UPV-TFM test,C=ES", leafK.getPublic(), false, null)
                .build(signer("SHA256withRSA", subK.getPrivate()), false, signer("ML-DSA-65", wrongAlt.getPrivate())),
                "alternative signature with a key that is not the sub CA's");
    }
}
