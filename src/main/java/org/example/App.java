package org.example;

import java.io.File;

/**
 * Hello world!
 *
 */
public class App {
    public static void main( String[] args ) {
        System.out.println(new CrptApi().sign("FBYBVZPJEZEAZGQFLGPSKVUPVDRMJJ", new File("test_certificate.pfx"), "TestPassword123"));
    }
}
