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

//    @Value("${signer.image.name}")
//    public String imageName;

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

//        InputStream imageResource = new FileInputStream(imageName);
//        signing.setImageBytes(readBytes(imageResource));

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
//         if (password.isEmpty()){
//             // In case password is not specified, it has to be pfx signature
//             logger.info("No password provided, signing with pfx file");
//             return sign(is, os);
//         }

           if(password == null || password.trim().isEmpty()){
            throw new IllegalArgumentException("DSC password is required for signing.");
           }
        boolean dscInsertedStatus = false;
        try {
            logger.info("Checking if DSC is inserted");
// //            logger.info("password is "+ password);
            dscInsertedStatus = isDscInserted(password);
            logger.debug("dscInsertedStatus is "+ dscInsertedStatus);
        } catch (Exception e) {
            logger.error("Error in fetching DSC status");
//             e.printStackTrace();
//             logger.info("DSC is not detected, signing with pfx file");
           throw new RuntimeException("Failed to detect DSC. Please ensure the dongle is inserted");
        }
        if (!dscInsertedStatus){
            logger.info("No DSC detected");
//             return sign(is, os);
            throw new RuntimeException("No DSC detected or incorrect password provided.");
        }
//         // Case of dsc based signature, change the code here
        logger.debug("DSC is detected, signing with dsc");
//         // Case of dsc based signature, change the code here
//         // InputStream ksInputStream = new FileInputStream(keystoreName); //:- .p12 file is loaded unnecessarily inside the DSC code path

        CreateVisibleSignatureMemDsc signing = new CreateVisibleSignatureMemDsc(password.toCharArray());

// //        InputStream imageResource = new FileInputStream(imageName);
// //        signing.setImageBytes(readBytes(imageResource));

        return signing.signPDF(is, os, tsaUrl, "Signature1");

    }


//:--- This is Only for DSC Dongle not for pfx file
// public Calendar sign(InputStream is, OutputStream os, String password)
//         throws KeyStoreException, CertificateException, IOException,
//                NoSuchAlgorithmException, UnrecoverableKeyException {

//     // Step 1: Validate password
//     if (password == null || password.trim().isEmpty()) {
//         throw new IllegalArgumentException("DSC password is required for signing.");
//     }

//     // Step 2: Check if DSC is inserted and password is correct
//     boolean dscInsertedStatus = false;
//     try {
//         logger.info("Checking if DSC is inserted...");
//         dscInsertedStatus = isDscInserted(password);
//         logger.debug("DSC Inserted Status: " + dscInsertedStatus);
//     } catch (Exception e) {
//         logger.error("Error while detecting DSC", e);
//         throw new RuntimeException("Failed to detect DSC. Please ensure the dongle is inserted.");
//     }

//     if (!dscInsertedStatus) {
//         throw new RuntimeException("No DSC detected or incorrect password provided.");
//     }

//     // Step 3: Proceed with DSC signing
//     logger.info("DSC detected and password valid. Proceeding to sign...");
//     CreateVisibleSignatureMemDsc signing = new CreateVisibleSignatureMemDsc(password.toCharArray());

//     return signing.signPDF(is, os, tsaUrl, "Signature1");
// }

    // public boolean isDscInserted(String password){
    //     logger.debug("password is "+ password);
    //     if (password.isEmpty()){
    //         return false;
    //     }
    //     String configPath = "config.cfg";
    //     Provider pkcs11Provider = Security.getProvider("SunPKCS11");
    //     pkcs11Provider = pkcs11Provider.configure(configPath);
    //     try {

    //         KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
    //         pkcs11KeyStore.load(null, password.toCharArray());
    //         java.util.Enumeration<String> aliases = pkcs11KeyStore.aliases();
    //         logger.debug("dected dsc fetching aliases");
    //         int noAliases = 0;
    //         List<String> aliasList = new ArrayList<>();
    //         while (aliases.hasMoreElements()) {
    //             String alias = aliases.nextElement();
    //             System.out.println("Alias: " + alias);
    //             noAliases += 1;
    //             aliasList.add(alias);
    //         }
    //         if (noAliases > 0) {
    //             return true;
    //         }

    //         return false;
    //     } catch (CertificateException e) {
    //         return false;
    //     } catch (IOException | KeyStoreException e) {
    //         return false;
    //     } catch (NoSuchAlgorithmException e) {
    //        return false;
    //     }
    // }

    public boolean isDscInserted(String password) {
    logger.debug("Checking DSC with password: " + password);
    if (password == null || password.trim().isEmpty()) {
        return false;
    }

    String configFilePath = "config.cfg";
    StringBuilder originalConfig = new StringBuilder();

    try (BufferedReader reader = new BufferedReader(new FileReader(configFilePath))) {
        String line;
        while ((line = reader.readLine()) != null) {
            originalConfig.append(line).append("\n");
        }
    } catch (IOException e) {
        logger.error("Failed to read config.cfg", e);
        return false;
    }

    String configContent = originalConfig.toString();
    String libraryLine = null;
    String nameLine = null;

    for (String line : configContent.split("\n")) {
        if (line.startsWith("library=")) {
            libraryLine = line;
        } else if (line.startsWith("name=")) {
            nameLine = line;
        }
    }

    if (libraryLine == null || nameLine == null) {
        logger.error("Invalid config.cfg: missing 'library=' or 'name='");
        return false;
    }
    for (int slot = 0; slot < 10; slot++) {
    String dynamicConfig =
        nameLine + "\n" +
        libraryLine + "\n" +
        "slot=" + slot + "\n";

    try {
        // Step 1: Write to temp config file
        File tempConfigFile = File.createTempFile("pkcs11-slot-" + slot, ".cfg");
        try (FileWriter writer = new FileWriter(tempConfigFile)) {
            writer.write(dynamicConfig);
        }

        // Step 2: Load with SunPKCS11
        Provider provider = Security.getProvider("SunPKCS11").configure(tempConfigFile.getAbsolutePath());
        KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(null, password.toCharArray());

        // Step 3: Check for aliases
        java.util.Enumeration<String> aliases = keyStore.aliases();
        List<String> aliasList = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            logger.info("Found DSC alias: " + alias);
            aliasList.add(alias);
        }

        if (!aliasList.isEmpty()) {
            logger.info("Valid DSC found in slot: " + slot);
            System.out.println("Yahan DSC laga hua hai: slot " + slot);
            return true;
        }

    } catch (Exception e) {
        logger.debug("Slot " + slot + " not valid or no token: " + e.getMessage());
    }
}



    logger.warn("No DSC found in any slot from 0–9");
    return false;
}



}
