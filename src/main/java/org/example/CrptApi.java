package org.example;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

public class CrptApi {

    public String sign(String sign, File cer, String password) {
        QualifiedElectronicSignatureSignificator<String> significator = new QualifiedElectronicSignatureSignificatorManager(new KeyStoreProviderManager("PKCS12"), new CMSSignedDataGeneratorProviderManager());
        return significator.sign(sign, cer, password, "SHA256withRSA", true);
    }

    private interface QualifiedElectronicSignatureSignificator<S> {
        S sign(S toSign, File certificateFile, String password, String signAlgorithm, boolean signSignature);
    }

    private static class QualifiedElectronicSignatureSignificatorManager implements QualifiedElectronicSignatureSignificator<String> {
        private final KeyStoreProvider keyStoreProvider;
        private final CMSSignedDataGeneratorProvider cmsSignedDataGeneratorProvider;

        public QualifiedElectronicSignatureSignificatorManager(KeyStoreProviderManager keyStoreProvider, CMSSignedDataGeneratorProviderManager cmsSignedDataGeneratorProvider) {
            Security.addProvider(new BouncyCastleProvider());
            this.keyStoreProvider = keyStoreProvider;
            this.cmsSignedDataGeneratorProvider = cmsSignedDataGeneratorProvider;
        }

        @Override
        public String sign(String toSign, File certificateFile, String password, String signAlgorithm, boolean signSignature) {
            KeyStore keyStore;
            String alias;
            PrivateKey privateKey;
            Certificate certificate;
            try {
                keyStore = keyStoreProvider.buildFrom(certificateFile, password.toCharArray());
                alias = keyStore.aliases().nextElement();
                privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
                certificate = keyStore.getCertificate(alias);

                CMSProcessableByteArray cmsData = new CMSProcessableByteArray(toSign.getBytes(StandardCharsets.UTF_8));
                CMSSignedData cmsSignedData = cmsSignedDataGeneratorProvider.buildFrom(certificate, buildSignerInfoGenerator(privateKey, certificate, signAlgorithm)).generate(cmsData, true);

                byte[] signedBytes = cmsSignedData.getEncoded();

                return Base64.getEncoder().encodeToString(signedBytes);
            } catch (KeyStoreException | NoSuchAlgorithmException | IOException |
                     UnrecoverableKeyException | CMSException e) {
                throw new RuntimeException(e);
            }
        }

        private SignerInfoGenerator buildSignerInfoGenerator(PrivateKey privateKey, Certificate certificate, String contentSignerMark) {
            try {
                ContentSigner contentSigner = new JcaContentSignerBuilder(contentSignerMark)
                        .setProvider("BC")
                        .build(privateKey);
                JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder()
                        .setProvider("BC");
                return new JcaSignerInfoGeneratorBuilder(digestCalculatorProviderBuilder.build()).build(contentSigner, new JcaX509CertificateHolder((X509Certificate) certificate));
            } catch (OperatorCreationException | CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private interface KeyStoreProvider {
        KeyStore buildFrom(File keystoreFile, char[] password);
    }

    public static class KeyStoreProviderManager implements KeyStoreProvider {
        private final KeyStore keyStore;

        public KeyStoreProviderManager(String keyStoreType) {
            try {
                this.keyStore = KeyStore.getInstance(keyStoreType);
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public KeyStore buildFrom(File keystoreFile, char[] password) {
            try {
                keyStore.load(Files.newInputStream(keystoreFile.toPath()), password);
            } catch (NoSuchAlgorithmException | IOException | CertificateException e) {
                throw new RuntimeException(e);
            }
            return keyStore;
        }
    }

    private interface CMSSignedDataGeneratorProvider {
        CMSSignedDataGenerator buildFrom(Certificate certificate, SignerInfoGenerator signerInfoGenerator);
    }

    public static class CMSSignedDataGeneratorProviderManager implements CMSSignedDataGeneratorProvider {

        @Override
        public CMSSignedDataGenerator buildFrom(Certificate certificate, SignerInfoGenerator signerInfoGenerator) {
            try {
                CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
                cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
                cmsSignedDataGenerator.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));
                return cmsSignedDataGenerator;
            } catch (CMSException | CertificateEncodingException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
