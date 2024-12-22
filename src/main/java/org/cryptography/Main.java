package org.cryptography;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) {

        String certificateLocation = "D:\\WorkSpace\\Certificates\\publicCertificate.cer";
        String data = "Hi, This is confidential data, this needs to be encrypted.";
        Encryption encryption = new Encryption();
        encryption.setCertificateLocation(certificateLocation);
        encryption.setDataToBeEncrypted(data.getBytes(StandardCharsets.UTF_8));
        String finalData = encryption.performEncryption();
        System.out.println("Encrypted Data is: \n\n"+ finalData);


    }
}
