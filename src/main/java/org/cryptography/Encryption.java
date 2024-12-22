package org.cryptography;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Encryption {

    private X509Certificate publicCertificate = null;
    private byte[] dataToBeEncrypted = null;
    public byte[] encryptedData = null;
    public String finalEncryptedData = null;
    public String certificateLocation = null;

    public void setPublicCertificate(X509Certificate publicCertificate) {
        this.publicCertificate = publicCertificate;
    }

    public void setDataToBeEncrypted(byte[] dataToBeEncrypted) {
        this.dataToBeEncrypted = dataToBeEncrypted;
    }

    public void setCertificateLocation(String certificateLocation) {
        this.certificateLocation = certificateLocation;
    }

    public String performEncryption() {
        //null checks before performing encryption.
        if (this.dataToBeEncrypted == null || certificateLocation == null) {
            return null;
        }
        //fetching the public certificate.
        this.publicCertificate = getX509Certificate(certificateLocation);
        if (publicCertificate == null) {
            return null;
        }
        Security.addProvider(new BouncyCastleProvider());
        CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
        try {
            JceKeyTransRecipientInfoGenerator bceKey = new JceKeyTransRecipientInfoGenerator(publicCertificate);
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(bceKey);
            CMSTypedData cmsTypedData = new CMSProcessableByteArray(dataToBeEncrypted);
            OutputEncryptor encryptor
                    = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(new BouncyCastleProvider()).build();

            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(cmsTypedData,encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();

            this.finalEncryptedData = Base64.getEncoder().encodeToString(encryptedData);
            String formattedData = formatEncryptedData(this.finalEncryptedData);

            this.finalEncryptedData = formattedData;

        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CMSException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        return finalEncryptedData;

    }

    public X509Certificate getX509Certificate(String certificateLocation) {
        X509Certificate certificate = null;
        try {
            Security.addProvider(new BouncyCastleProvider());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream(certificateLocation));
            if (certificate == null) {
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return certificate;
    }

    public String formatEncryptedData(String data) {
        StringBuilder formattedString = new StringBuilder();
        int length = data.length();
        int lineLength = 64;

        for (int i = 0; i < length; i += lineLength) {
            if (i + lineLength < length) {
                formattedString.append(data, i, i + lineLength).append(System.lineSeparator());
            } else {
                formattedString.append(data.substring(i)).append(System.lineSeparator());
            }
        }

        return formattedString.toString();
    }

}