package org.example;

import java.io.File;
import java.util.concurrent.TimeUnit;

/**
 * Hello world!
 *
 */

/**
 * Пример использования класса {@link CrptApi}
 */
public class App {
    public static void main( String[] args ) {
        CrptApi crptApi = new CrptApi(new File("test_certificate.pfx"), "TestPassword123", TimeUnit.SECONDS, 5);
        CrptApi.UserDataDTO userDataDTO = crptApi.getSignedAuthorizationData();
        String token = crptApi.getAuthenticationToken(userDataDTO);
        crptApi.createDocument(new CrptApi.DocumentDTO(), token);
    }
}
