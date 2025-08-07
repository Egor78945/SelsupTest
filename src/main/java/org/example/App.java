package org.example;

import java.io.File;

/**
 * Hello world!
 *
 */
public class App {
    public static void main( String[] args ) {
        System.out.println(new CrptApi(new File("test_certificate.pfx")).sign("TestPassword123"));
    }
}
