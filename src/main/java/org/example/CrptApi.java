package org.example;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.StringEntity;
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
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Класс, предоставляющий доступ к API "Честного знака"
 */
public class CrptApi {
    /**
     * Ссылка на файл с электронной подписью
     */
    private final File pfxCertificate;
    /**
     * Пароль к файлу с электронной подписью
     */
    private final String password;
    /**
     * Единица времени, через которую будет выполняться обнуление счётчика вызова метода и освобождение потоков
     */
    private final TimeUnit limitUnit;
    /**
     * Текущее количество потоков, пытающихся вызвать метод
     */
    private AtomicInteger currentCallCount;
    /**
     * Максимальное количество вызовов метода за {@link TimeUnit}
     */
    private final int limitRate;
    private final Gson gson;
    private final QualifiedElectronicSignatureSignificator<String> significator;
    private final WebClient<String> webClient;
    private final AuthenticationService<UserDataDTO> authenticationService;
    private final DocumentService<DocumentDTO> documentService;

    public CrptApi(File pfxCertificate, String password, TimeUnit limitUnit, int limitRate) {
        this.pfxCertificate = pfxCertificate;
        this.password = password;
        this.limitUnit = limitUnit;
        this.limitRate = limitRate;
        this.currentCallCount = new AtomicInteger(0);
        webClient = new WebClientManager(HttpClients.createDefault());
        gson = new Gson();
        authenticationService = new AuthenticationServiceManager(gson, webClient);
        documentService = new DocumentServiceManager(webClient, gson);
        significator = new QualifiedElectronicSignatureSignificatorManager(new KeyStoreProviderManager("PKCS12"), new CMSSignedDataGeneratorProviderManager());
        Thread monitoringThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(limitUnit.toMillis(1));
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                currentCallCount.set(0);
                synchronized (this) {
                    notifyAll();
                }
            }
        });
        monitoringThread.setDaemon(true);
        monitoringThread.start();
    }

    /**
     * Получить авторизационные данные
     *
     * @return {@link UserDataDTO}
     */
    public UserDataDTO getSignedAuthorizationData() {
        UserDataDTO userData = authenticationService.authorize();
        userData.setData(significator.sign(userData.getData(), pfxCertificate, password, "SHA256withRSA", true));
        return userData;
    }

    /**
     * Получить аутентификационный токен, использу пользовательские авторизационные данные @{@link UserDataDTO}
     *
     * @param userData пользовательские данные {@link UserDataDTO}
     * @return Токен аутентификации
     */
    public String getAuthenticationToken(UserDataDTO userData) {
        return authenticationService.authenticate(userData);
    }

    /**
     * Создать новый документ
     *
     * @param document модель документа {@link DocumentDTO}
     * @param token    Токент аутентификации
     * @return Уникальный идентификатор новосозданного документа
     */
    public synchronized String createDocument(DocumentDTO document, String token) {
        currentCallCount.incrementAndGet();
        while (currentCallCount.get() >= limitRate) {
            try {
                wait();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            createDocument(document, token);
        }
        return documentService.create(document, token);
    }

    private interface DocumentService<D extends DocumentDTO> {
        String create(D document, String token);
    }

    private static class DocumentServiceManager implements DocumentService<DocumentDTO> {
        private final WebClient<String> webClient;
        private final Gson gson;

        public DocumentServiceManager(WebClient<String> webClient, Gson gson) {
            this.webClient = webClient;
            this.gson = gson;
        }

        @Override
        public String create(DocumentDTO document, String token) {
            try {
                HttpPost httpPost = HttpRequestBuilder.buildPost(new URI(String.format("https://ismp.crpt.ru/api/v3/auth/cert?pg=%s", document.product_group)), Map.of("content-type", "application/json", "charset", "UTF-8", "Authorization", String.format("Bearer %s", token)));
                httpPost.setEntity(new StringEntity(gson.toJson(document)));
                return JsonParser.parseString(webClient.post(httpPost)).getAsJsonObject().get("value").getAsString();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
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

    public interface WebClient<R> {
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

    private interface AuthenticationService<T> {
        T authorize();

        String authenticate(T data);
    }

    private static class AuthenticationServiceManager implements AuthenticationService<UserDataDTO> {
        private final Gson gson;
        private final WebClient<String> webClient;

        public AuthenticationServiceManager(Gson gson, WebClient<String> webClient) {
            this.gson = gson;
            this.webClient = webClient;
        }

        @Override
        public UserDataDTO authorize() {
            try {
                return gson.fromJson(webClient.get(HttpRequestBuilder.buildGet(new URI("https://ismp.crpt.ru/api/v3/auth/cert/key"), Map.of("content-type", "application/json", "charset", "UTF-8"))), UserDataDTO.class);
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String authenticate(UserDataDTO data) {
            try {
                HttpPost httpPost = HttpRequestBuilder.buildPost(new URI("https://ismp.crpt.ru/api/v3/auth/cert"), Map.of("content-type", "application/json", "charset", "UTF-8"));
                httpPost.setEntity(new StringEntity(gson.toJson(data)));
                return JsonParser.parseString(webClient.post(httpPost)).getAsJsonObject().get("token").getAsString();
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static class UserDataDTO {
        private String uuid;
        private String data;

        public UserDataDTO(String uuid, String data) {
            this.uuid = uuid;
            this.data = data;
        }

        public UserDataDTO() {
        }

        public String getUuid() {
            return uuid;
        }

        public void setUuid(String uuid) {
            this.uuid = uuid;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            UserDataDTO userData = (UserDataDTO) o;
            return Objects.equals(uuid, userData.uuid);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(uuid);
        }

        @Override
        public String toString() {
            return "UserData{" +
                    "uuid='" + uuid + '\'' +
                    ", data='" + data + '\'' +
                    '}';
        }
    }

    public static class DocumentDTO {
        private String document_format;
        private String product_document;
        private String product_group;
        private String signature;
        private String type;

        public DocumentDTO(String document_format, String product_document, String product_group, String signature, String type) {
            this.document_format = document_format;
            this.product_document = product_document;
            this.product_group = product_group;
            this.signature = signature;
            this.type = type;
        }

        public DocumentDTO() {
        }

        public String getDocument_format() {
            return document_format;
        }

        public void setDocument_format(String document_format) {
            this.document_format = document_format;
        }

        public String getProduct_document() {
            return product_document;
        }

        public void setProduct_document(String product_document) {
            this.product_document = product_document;
        }

        public String getProduct_group() {
            return product_group;
        }

        public void setProduct_group(String product_group) {
            this.product_group = product_group;
        }

        public String getSignature() {
            return signature;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            DocumentDTO document = (DocumentDTO) o;
            return Objects.equals(document_format, document.document_format) && Objects.equals(product_document, document.product_document) && Objects.equals(product_group, document.product_group) && Objects.equals(signature, document.signature) && Objects.equals(type, document.type);
        }

        @Override
        public int hashCode() {
            return Objects.hash(document_format, product_document, product_group, signature, type);
        }

        @Override
        public String toString() {
            return "Document{" +
                    "document_format='" + document_format + '\'' +
                    ", product_document='" + product_document + '\'' +
                    ", product_group='" + product_group + '\'' +
                    ", signature='" + signature + '\'' +
                    ", type='" + type + '\'' +
                    '}';
        }
    }
}
