package org.example;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
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
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class CrptApi {

    public String sign(String sign, File cer, String password) {
        QualifiedElectronicSignatureSignificator<String> significator = new QualifiedElectronicSignatureSignificatorManager(new KeyStoreProviderManager("PKCS12"), new CMSSignedDataGeneratorProviderManager());
        WebClient<String> webClient = new WebClientManager(HttpClients.createDefault());
        try {
            HttpGet get = HttpRequestBuilder.buildGet(new URI("https://ismp.crpt.ru/api/v3/auth/cert/key"), null);
            String closeableHttpResponse = webClient.get(get);
            System.out.println(closeableHttpResponse);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
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

    private interface WebClient <R> {
        R post(HttpPost httpEntity);

        R get(HttpGet httpGet);
    }

    public static class WebClientManager implements WebClient<String> {
        private final CloseableHttpClient httpClient;

        public WebClientManager(CloseableHttpClient httpClient) {
            this.httpClient = httpClient;
        }

        @Override
        public String post(HttpPost httpEntity) {
            try {
                return httpClient.execute(httpEntity, new BasicHttpClientResponseHandler());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String get(HttpGet httpGet) {
            try {
                return httpClient.execute(httpGet, new BasicHttpClientResponseHandler());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class HttpRequestBuilder {
        private static HttpGet buildGet(URI uri, Map<String, String> headers) {
            HttpGet httpGet = new HttpGet(uri);
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    httpGet.addHeader(header.getKey(), header.getValue());
                }
            }
            return httpGet;
        }

        public static HttpPost buildPost(URI uri, Map<String, String> headers) {
            HttpPost httpPost = new HttpPost(uri);
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    httpPost.addHeader(header.getKey(), header.getValue());
                }
            }
            return httpPost;
        }
    }
}
