package org.example;

import java.io.File;
import java.util.Arrays;
import java.util.Base64;

/**
 * Hello world!
 *
 */
public class App {
    public static void main( String[] args ) {
        System.out.println(new CrptApi().sign("abc", new File("test_certificate.pfx"), "TestPassword123"));
    }
}
