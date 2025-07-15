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

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.security.auth.x500.X500Principal;

/**
 * This class signs using the dsc dongle
 */
public abstract class CreateSignatureBaseDsc implements SignatureInterface
{
    private static final Logger logger = LogManager.getLogger(Signer.class);
    private PrivateKey privateKey;
    private Certificate[] certificateChain;
    private String tsaUrl;
    private boolean externalSigning;
    private char[] pin;

    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that should be used for the
     * signature.
     *
     * @param pin is the pin for the keystore / private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException if the certificate is not valid as signing time
     * @throws IOException if no certificate could be found
     */
    public CreateSignatureBaseDsc(char[] pin)
            throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, UnrecoverableKeyException {
        // This function is currently grabbing the certificate form the pfx file. Need to change that
        // AIM of this function is to create the certificate chain
        this.pin = pin;
        System.out.println("password is "+pin.toString());
        String configPath = "config.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(configPath);
        KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        pkcs11KeyStore.load(null, pin);
        java.util.Enumeration<String> aliases = pkcs11KeyStore.aliases();
        String alias;
        Certificate cert = null;
        while (aliases.hasMoreElements()&&cert == null) {
            alias = aliases.nextElement();
            setPrivateKey((PrivateKey) pkcs11KeyStore.getKey(alias, pin));
            Certificate[] certChain = pkcs11KeyStore.getCertificateChain(alias);
            if (certChain != null)
            {   logger.debug("certificate chain found");
                setCertificateChain(certChain);
                cert = certChain[0];
                if (cert instanceof X509Certificate)
                {
                    // avoid expired certificate
//                    ((X509Certificate) cert).checkValidity();

                    SigUtils.checkCertificateUsage((X509Certificate) cert);
                }
            } else {
                logger.debug("certificate chain not found");
                logger.debug("checking for the certificate ");
                Certificate certificate = pkcs11KeyStore.getCertificate(alias);
                if (certificate!=null){
                    logger.debug("certificate found");
                    logger.debug(certificate.toString());
                }
            }
        }
        if (cert == null)
        {
            throw new IOException("Could not find certificate");
        }
    }
    public final void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public final void setCertificateChain(final Certificate[] certificateChain)
    {
        this.certificateChain = certificateChain;
    }

    public Certificate[] getCertificateChain()
    {
        return certificateChain;
    }

    public void setTsaUrl(String tsaUrl)
    {
        this.tsaUrl = tsaUrl;
    }

    /**
     * SignatureInterface sample implementation.
     *<p>
     * This method will be called from inside of the pdfbox and create the PKCS #7 signature.
     * The given InputStream contains the bytes that are given by the byte range.
     *<p>
     * This method is for internal use only.
     *<p>
     * Use your favorite cryptographic library to implement PKCS #7 signature creation.
     * If you want to create the hash and the signature separately (e.g. to transfer only the hash
     * to an external application), read <a href="https://stackoverflow.com/questions/41767351">this
     * answer</a> or <a href="https://stackoverflow.com/questions/56867465">this answer</a>.
     *
     * @throws IOException
     */

    @Override
    public byte[] sign(InputStream content) throws IOException
    {
        // cannot be done private (interface)
        try
        {
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = getSignature(content, this.pin);
            if (tsaUrl != null && tsaUrl.length() > 0)
            {
                ValidationTimeStamp validation = new ValidationTimeStamp(tsaUrl);
                signedData = validation.addSignedTimeStamp(signedData);

            }
            return signedData.getEncoded();
        }
        catch (GeneralSecurityException | CMSException | OperatorCreationException e)
        {
            throw new IOException(e);
        }
    }

    /**
     * Set if external signing scenario should be used.
     * If {@code false}, SignatureInterface would be used for signing.
     * <p>
     *     Default: {@code false}
     * </p>
     * @param externalSigning {@code true} if external signing should be performed
     */
    public void setExternalSigning(boolean externalSigning)
    {
        this.externalSigning = externalSigning;
    }

    public boolean isExternalSigning()
    {
        return externalSigning;
    }

    /**
     * Given the input stream and the password, signs by using the first alias in the dsc dongle
     * Also extract the certficate from the dongle  and should append the certificate to the signature
     * @param content
     * @param password
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws CMSException
     * @throws OperatorCreationException
     */
    public CMSSignedData getSignature(InputStream content, char[] password) throws KeyStoreException, CertificateException, IOException,
            NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException, CMSException, OperatorCreationException {
        String configPath = "config.cfg";
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(configPath);
        KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
        pkcs11KeyStore.load(null, password);
        java.util.Enumeration<String> aliases = pkcs11KeyStore.aliases();
        int noAliases = 0;
        List<String> aliasList = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
            noAliases += 1;
            aliasList.add(alias);
        }
        System.out.println("Total number of alias are: " + noAliases);
        // Iterate through aliasList to find a valid alias with a non-null private key
        String selectedAlias = null;
        PrivateKey privateKey = null;

        for (String alias : aliasList) {
            try {
                // Get the private key for the alias
                privateKey = (PrivateKey) pkcs11KeyStore.getKey(alias, password);

                if (privateKey != null) {
                    // If the private key is non-null, select this alias and break the loop
                    selectedAlias = alias;
                    break;
                }
            } catch (Exception e) {
                // Handle exceptions for each alias (e.g., private key not accessible)
                logger.debug("Unable to retrieve private key for alias: " + alias, e);
            }
        }

        if (selectedAlias != null && privateKey != null) {
            // Fetch the certificate associated with the selected alias
            X509Certificate cert = (X509Certificate) pkcs11KeyStore.getCertificate(selectedAlias);
            logger.debug("Using certificate: " + cert.toString());

            // Create the CMSSignedDataGenerator and build the signature
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA");
            contentSignerBuilder.setProvider(pkcs11Provider);
            ContentSigner sha1Signer = contentSignerBuilder.build(privateKey);

            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(cert)));

            // Create a CMSProcessable for the content (msg)
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);

            // Generate the signed data
            CMSSignedData signedData = gen.generate(msg, false);

            // Return the signed data
            return signedData;
        } else {
            System.out.println("No valid alias with a non-null private key found.");
            throw new SignatureException("Unable to sign - No valid alias found with private key");
        }

    }

    public String get_signer_name() {
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
}