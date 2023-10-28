package gr.hcg.sign;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.awt.geom.Rectangle2D;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

@Component
public class Signer {
    private static final Logger logger = LogManager.getLogger(Signer.class);

    @Value("${signer.keystore.pin}")
    public String keystorePin;

    @Value("${signer.keystore.name}")
    public String keystoreName;

    @Value("${signer.image.name}")
    public String imageName;

    @Value("${signer.tsaurl}")
    public String tsaUrl;

    public static byte[] readBytes(InputStream is ) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;
        byte[] data = new byte[16384];

        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        return buffer.toByteArray();

    }

    public static void setIfNotNull(CreateVisibleSignatureMem signing, String signName, String signLocation, String signReason, String visibleLine1, String visibleLine2, String uuid, String qrcode) {

        if(signName!=null) {
            signing.signatureName = signName;
        }
        if(signLocation!=null) {
            signing.signatureLocation = signLocation;
        }
        if(signReason!=null) {
            signing.signatureReason = signReason;
        }
        if(visibleLine1!=null) {
            signing.visibleLine1 = visibleLine1;
        }
        if(visibleLine2!=null) {
            signing.visibleLine2 = visibleLine2;
        }
        if(uuid!=null) {
            signing.uuid = uuid;
        }
       
    }

    public Calendar sign(InputStream is, OutputStream os) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        logger.info("Default signing with pfx file");
        InputStream ksInputStream = new FileInputStream(keystoreName);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        char[] pin = keystorePin.toCharArray();
        keystore.load(ksInputStream, pin);

        CreateVisibleSignatureMem signing = new CreateVisibleSignatureMem(keystore, pin.clone());

        InputStream imageResource = new FileInputStream(imageName);
        signing.setImageBytes(readBytes(imageResource));

        return signing.signPDF(is, os, tsaUrl, "Signature1");
        }
        /**
         * Calls Signing.signPdf to sign the pdf and returns the Calendar class
         * @param is
         * @param os
         * @return
         * @throws KeyStoreException
         * @throws CertificateException
         * @throws IOException
         * @throws NoSuchAlgorithmException
         * @throws UnrecoverableKeyException
         */
    public Calendar sign(InputStream is, OutputStream os, String password) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // This function should decide whether the dsc has been inserted or not and in case no, then it should use pfx for signing
        if (password.isEmpty()){
            // In case password is not specified, it has to be pfx signature
            logger.info("No password provided, signing with pfx file");
            return sign(is, os);
        }
        if (! isDscInserted(password)){
            logger.info("No DSC detected, signing with pfx file");
            return sign(is, os);
        }
        // Case of dsc based signature, change the code here
        InputStream ksInputStream = new FileInputStream(keystoreName);

        CreateVisibleSignatureMemDsc signing = new CreateVisibleSignatureMemDsc(password.toCharArray());

        InputStream imageResource = new FileInputStream(imageName);
        signing.setImageBytes(readBytes(imageResource));

        return signing.signPDF(is, os, tsaUrl, "Signature1");

    }
    public boolean isDscInserted(String password){
        logger.debug("password is "+ password);
        if (password.isEmpty()){
            return false;
        }
        String configPath = "config.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(configPath);
        try {
            KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            pkcs11KeyStore.load(null, password.toCharArray());
            java.util.Enumeration<String> aliases = pkcs11KeyStore.aliases();
            logger.debug("dected dsc fetching aliases");
            int noAliases = 0;
            List<String> aliasList = new ArrayList<>();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                System.out.println("Alias: " + alias);
                noAliases += 1;
                aliasList.add(alias);
            }
            if (noAliases > 0) {
                return true;
            }

            return false;
        } catch (CertificateException e) {
            return false;
        } catch (IOException | KeyStoreException e) {
            return false;
        } catch (NoSuchAlgorithmException e) {
           return false;
        }
    }


}
