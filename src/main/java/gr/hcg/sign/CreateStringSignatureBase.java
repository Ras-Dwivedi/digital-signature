/*
 * Copyright 2015 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gr.hcg.sign;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.json.JSONException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.util.Properties;

import javax.security.auth.x500.X500Principal;
//@Component
public class CreateStringSignatureBase
{
    private static final String FILE_PATH = "./src/main/resources/application.properties";

    private static Properties properties;
    static {
        InputStream inputStream = CreateStringSignatureBase.class.getClassLoader().getResourceAsStream("application.properties");
        properties = new Properties();
        try {
            properties.load(inputStream);
        } catch (Exception e) {
            e.printStackTrace();

        }
//        try (FileInputStream fis = new FileInputStream(FILE_PATH)) {
//            properties.load(fis);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }
//    public static String getPropertyValue(String key) {
//        return properties.getProperty(key);
//    }

    private PrivateKey privateKey;
    private Certificate[] certificateChain;
    private String tsaUrl;
    private boolean externalSigning;
    private KeyStore keyStore;
    private char[] pin;
    private Provider provider;
    private boolean isDscDetected;
    private static final Logger logger = LogManager.getLogger(Signer.class);

    public Certificate[] getCertChain(KeyStore keystore, char[] pin) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Enumeration<String> aliases = keystore.aliases();
        String alias;
        Certificate cert = null;
        while (cert == null && aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
            Certificate[] certChain = keystore.getCertificateChain(alias);
            if(!(checkValidity(certChain)) ){
                System.out.println("Invalid cert chain");
            }
            return certChain;
        }
        return new Certificate[0];
    }


    /**
     * This methos checks the validity of all the certfiicates in the certificate chain
     * @param certChain
     * @return
     */
    public boolean checkValidity(Certificate[] certChain) {
        for (int i=0; i< certChain.length;i++){
            try {
                Certificate cert = certChain[i];
                if (cert instanceof X509Certificate) {
                    ((X509Certificate) cert).checkValidity();
                    SigUtils.checkCertificateUsage((X509Certificate) cert);
                }
            } catch (Exception e){
                e.printStackTrace();
                return false;
            }
        }
        return true;
    }
    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that should be used for the
     * signature.
     *
     * @param keystore is a pkcs12 keystore.
     * @param pin is the pin for the keystore / private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException if the certificate is not valid as signing time
     * @throws IOException if no certificate could be found
     */
    public CreateStringSignatureBase(KeyStore keystore, char[] pin)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
    {
        // grabs the first alias from the keystore and get the private key. An
        // alternative method or constructor could be used for setting a specific
        // alias that should be used.
        this.keyStore = keyStore;
        this.pin = pin;
        this.certificateChain = getCertChain(keystore,pin);
        this.provider = null;
        this.isDscDetected = false;
    }

    /**
     * Default constructor with no values
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public CreateStringSignatureBase() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
     assignDefaultCertChain();
    }

    /**
     * Constructor that signs using the DSC keys
     * @param password
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public CreateStringSignatureBase(String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
//        if (password.isEmpty()){
//            assignDefaultCertChain();
//            return;
//        }
//        if (!isDscDetected(password)){
//            assignDefaultCertChain();
//            return;
//        }
//        assignDscCertChain(password.toCharArray());
        assignDefaultCertChain();
    }


    /**
     * from the default pfx file, creates the certificate chain and assigns it to the class variable
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public void assignDefaultCertChain() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        String keystoreName = properties.getProperty("signer.keystore.name");
        String keystorePin = properties.getProperty("signer.keystore.pin");

        InputStream ksInputStream = new FileInputStream(keystoreName);
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        char[] pin = keystorePin.toCharArray();
        keystore.load(ksInputStream, pin);
        this.keyStore = keyStore;
        this.pin = pin;
        this.certificateChain = getCertChain(keystore,pin);
        this.provider = null;
        this.isDscDetected = false;

    }
//    public void assignDscCertChain(char[] pin) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
//        String configPath = "config.cfg";
//        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
//        pkcs11Provider = pkcs11Provider.configure(configPath);
//        KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
//        pkcs11KeyStore.load(null, pin);
//        this.keyStore = pkcs11KeyStore;
//        this.pin = pin;
//        this.certificateChain = getCertChain(pkcs11KeyStore,pin);
//        this.provider = pkcs11Provider;
//        this.isDscDetected = true;
//    }

    /**
     *
     * Returns whether the DSC is detected or not
     * @param password
     * @return
//     */
//    public boolean isDscDetected(String password){
//        logger.debug("password is "+ password);
//        if (password.isEmpty()){
//            return false;
//        }
//        String configPath = "config.cfg";
//        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
//        pkcs11Provider = pkcs11Provider.configure(configPath);
//        try {
//            KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
//            pkcs11KeyStore.load(null, password.toCharArray());
//            java.util.Enumeration<String> aliases = pkcs11KeyStore.aliases();
//            logger.debug("dected dsc fetching aliases");
//            int noAliases = 0;
//            List<String> aliasList = new ArrayList<>();
//            while (aliases.hasMoreElements()) {
//                String alias = aliases.nextElement();
//                System.out.println("Alias: " + alias);
//                noAliases += 1;
//                aliasList.add(alias);
//            }
//            if (noAliases > 0) {
//                return true;
//            }
//
//            return false;
//        } catch (CertificateException e) {
//            return false;
//        } catch (IOException | KeyStoreException e) {
//            return false;
//        } catch (NoSuchAlgorithmException e) {
//            return false;
//        }
//    }
    /**
     * Sets the private key
     * Since the private key is not accessible in case of PKCS12, this should not be used there
     * @param privateKey
     */
    public final void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    /**
     * Sets the Certificate chain
     * @param certificateChain
     */
    public final void setCertificateChain(final Certificate[] certificateChain)
    {
        this.certificateChain = certificateChain;
    }

    /**
     * getter for the Certificate Chain
     * @return
     */
    public Certificate[] getCertificateChain()
    {
        return this.certificateChain;
    }

    /**
     * Gets TSA URL
     * Ideally this function should not be used
     * @param tsaUrl
     */
    public void setTsaUrl(String tsaUrl)
    {
        this.tsaUrl = tsaUrl;
    }

    /**
     * Signs the message using the key stored in the class
     * returns the base64 encoded string of CMSSignedData
     * @param msg
     * @return
     * @throws IOException
     */
//    @Override
    public CMSSignedData sign(String msg) throws IOException
    {
        try
        {

            //
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = (X509Certificate) this.certificateChain[0];
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
            ContentSigner sha1Signer;
//            if(isDscDetected){
//                contentSignerBuilder.setProvider(this.provider);
//                sha1Signer = contentSignerBuilder.build(this.privateKey);
//
//            } else {
//                sha1Signer = contentSignerBuilder.build(this.privateKey);
//
//            }
            sha1Signer = contentSignerBuilder.build(this.privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(this.certificateChain)));
            CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(msg.getBytes()), true);
            return signedData;
        }
        catch (Exception e)
        {
            throw new IOException(e);
        }
    }


    /**
     * This method takes the cms data as base64 encoded string and then verifies the signature
     * @param cmsData
     * @return
     * @throws
     */
    public boolean verifyString(String cmsData) throws CMSException, CertificateException, IOException, OperatorCreationException {
        CMSSignedData cmsSignedData;
        try {
            cmsSignedData = getCmsFromBase64(cmsData);
        } catch (CMSException e) {
            logger.debug(e.getStackTrace());
            throw e;
        } catch (DecoderException e) {
            logger.debug(e.getStackTrace());
            throw new CMSException("unable to convert string to CMSSignedData");
        } catch (Exception e) {
            logger.debug(e.getStackTrace());
            throw new CMSException("error in converting base64 to CMSSignedData");
        }
        logger.debug("Successfully created the CMSSignedData Object");
        return verify(cmsSignedData);

    }

    /**
     * Returns the signer name for the first certificate in the certificate chain
     * @return Signer name
     */
    public String getSignerName() {
        Certificate certificate = this.certificateChain[0];
        try {
            X500Principal x500Principal = ((X509Certificate)certificate).getSubjectX500Principal();
            String dn = x500Principal.getName(X500Principal.RFC1779);
            String cn = null;

            String[] dnComponents = dn.split(", ");
            for (String component : dnComponents) {
                if (component.startsWith("CN=")) {
                    cn = component.substring(3);
                    break; // Once found, exit the loop
                }
            }

            if (cn != null) {
                // 'cn' contains the Common Name
                return cn;
            } else {
                // Common Name not found
                throw new Exception("name not found");
            }
            // 'name' will contain the distinguished name (DN) of the signer
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Converts the bytes to hex string
     * @param byteArray
     * @return
     */
    public String bytesToHex(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteArray) {
            // Convert the byte to a 2-character hexadecimal representation
            String hex = String.format("%02X", b);
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Given the CMSSignedData, returns the message that was signed in the signed data
     * @param signedData
     * @return message plain text : String
     * @throws IOException
     */
    public String getMessage(CMSSignedData signedData) throws IOException {
        CMSProcessable signedContent = signedData.getSignedContent();
        if (signedContent instanceof CMSProcessableByteArray) {
            byte[] contentBytes = ((CMSProcessableByteArray) signedContent).getInputStream().readAllBytes();
            String content = new String(contentBytes, "UTF-8"); // Adjust the encoding as needed
            return content;
        } else {
            throw new IOException("unable to read the message");
            // Handle other types of CMSProcessable if needed
        }
    }

    /**
     * From the CMS signed data, returns the signer information
     * @param signedData
     * @return
     */
    public String getSignerInfo(CMSSignedData signedData){
        SignerInformationStore signerInfos = signedData.getSignerInfos();
        System.out.println("Total signers: "+signerInfos.getSigners().size());
        for (SignerInformation signerInfo : signerInfos.getSigners()) {
            System.out.println("Signer Identity:");
            System.out.println(signerInfo.getSID().getIssuer());
            System.out.println(signerInfo.getSID().getSerialNumber());
//            return signerInfo.getSID().toString();
            return signerInfo.getSID().getIssuer().toString();
        }
        return null;
    }

    /**
     * Extracts the signature from the CMSSignedData
     * @param signedData
     * @return
     */
    public String getSignature(CMSSignedData signedData){
        SignerInformationStore signerInfos = signedData.getSignerInfos();
        System.out.println("Total signers: "+signerInfos.getSigners().size());
        for (SignerInformation signerInfo : signerInfos.getSigners()) {
            System.out.println("Signature:");
            byte[] signatureBytes = signerInfo.getSignature();
            return  bytesToHex(signatureBytes);
        }
        return null;
    }


    /**
     * returns the base64 version of the CMSSignedData
     * @param signedData
     * @return
     * @throws IOException
     * @throws JSONException
     */
    public String cmsToBase64(CMSSignedData signedData) throws IOException, JSONException {
        byte[] bytes = signedData.getEncoded();
        String base64EncodedBytes = Base64.toBase64String(bytes);
        return base64EncodedBytes;
    }

    /**
     * loads the CMSSignedData object from the base64 String
     * @param base64String
     * @return
     * @throws CMSException
     */
    public CMSSignedData getCmsFromBase64(String base64String) throws CMSException {
        logger.debug("the String is %s", base64String);
        logger.debug(base64String);
        byte[] cmsSignedDataBytes = Base64.decode(base64String);
        logger.debug("comverted string to cms bytes");
        ByteArrayInputStream bis = new ByteArrayInputStream(cmsSignedDataBytes);
        CMSSignedData signedData = new CMSSignedData(bis);
        return signedData;
    }

    /**
     * Returns the collection of the certificates in the signed data
     * @param cmsSignedData
     * @return
     * @throws CertificateParsingException
     */
    public Collection<X509Certificate> getCertificate(CMSSignedData cmsSignedData) throws CertificateParsingException {
        Collection<X509CertificateHolder> certificateHolders = cmsSignedData.getCertificates().getMatches(null);
        Collection<X509Certificate> certificates = new ArrayList<>();
        for (X509CertificateHolder certificateHolder : certificateHolders) {
            X509Certificate certificate = new X509CertificateObject(certificateHolder.toASN1Structure());
            certificates.add(certificate);
        }
        return certificates;
    }

    /**
     * Returns the first certificate in the Signed data
     * @param cmsSignedData
     * @return
     * @throws CertificateParsingException
     */
    public X509Certificate getFirstCertificate(CMSSignedData cmsSignedData) throws CertificateException, IOException {
        Collection<X509CertificateHolder> certificateHolders = cmsSignedData.getCertificates().getMatches(null);
        for (X509CertificateHolder certificateHolder : certificateHolders) {
            return getCertificate(certificateHolder);
        }
        return null;
    }

    /**
     * Extracts the public key from the certificate
     * This function is partially developed and returns the hex encoding of the public key
     * ToDO: in case of RSA public key, return the modulus and the exponent separately
     * @param cert
     */
    public void getPublicKey(X509Certificate cert){
        PublicKey publicKey = cert.getPublicKey();
        System.out.println("Algorithm: " + publicKey.getAlgorithm());
        System.out.println("Format: " + publicKey.getFormat());
        System.out.println("key: " + bytesToHex(publicKey.getEncoded()));
    }

    /**
     * Verifies whether the CMS signed data is correct or not
     * verifies the signature on the signed data, from the signers
     * Verifies the signer certificate with the help of the providers
     * @param cmsSignedData
     * @return
     * @throws CertificateException
     * @throws IOException
     * @throws OperatorCreationException
     */
    public boolean verify(CMSSignedData cmsSignedData) throws CertificateException, IOException, OperatorCreationException {
        Iterator<SignerInformation> it = cmsSignedData.getSignerInfos().getSigners().iterator();
        boolean verified = true;
        while (it.hasNext()) {
            SignerInformation signerInformation = it.next();
            X509Certificate x509Certificate = getFirstCertificate(cmsSignedData);
            getPublicKey(x509Certificate);
//        verify the certificate. Ideally you should get the certificate from somewhere else and then match it?
            SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().build(x509Certificate);
            try {
                Boolean verify = signerInformation.verify(signerInformationVerifier); // only verifies the signer information and not the signature
                if (verify == false) {
                    verified = false;
                }
            } catch (Exception e) {
                System.out.println(e);
//            return false;
            }
        }
        return verified;

    }

    /**
     * Extracts the X509 Certificate from the certificate holder
     * @param certificateHolder
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static X509Certificate getCertificate(X509CertificateHolder certificateHolder) throws IOException, CertificateException {
        byte[] encodedCertificate = certificateHolder.getEncoded();

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(encodedCertificate));

        return certificate;
    }
}