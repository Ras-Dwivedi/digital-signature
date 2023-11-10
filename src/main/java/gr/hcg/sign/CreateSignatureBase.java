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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import javax.security.auth.x500.X500Principal;

public abstract class CreateSignatureBase implements SignatureInterface
{
    private PrivateKey privateKey;
    private Certificate[] certificateChain;
    private String tsaUrl;
    private boolean externalSigning;

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
    public CreateSignatureBase(KeyStore keystore, char[] pin)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException
    {
        // grabs the first alias from the keystore and get the private key. An
        // alternative method or constructor could be used for setting a specific
        // alias that should be used.
        Enumeration<String> aliases = keystore.aliases();
        String alias;
        Certificate cert = null;
        while (cert == null && aliases.hasMoreElements())
        {
            alias = aliases.nextElement();
            setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
            Certificate[] certChain = keystore.getCertificateChain(alias);
            if (certChain != null)
            {
                setCertificateChain(certChain);
                cert = certChain[0];
                if (cert instanceof X509Certificate)
                {
                    // avoid expired certificate
                    ((X509Certificate) cert).checkValidity();

                    SigUtils.checkCertificateUsage((X509Certificate) cert);
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
//    @Override
    @Override
    public byte[] sign(InputStream content) throws IOException
    {
        // cannot be done private (interface)
        try
        {
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = (X509Certificate) certificateChain[0];
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            String testString = "ras";
//            CMSProcessableInputStream msg = stringToCMSProcessableInputStream(testString);
            CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(testString.getBytes()), false);
            if (tsaUrl != null && tsaUrl.length() > 0)
            {
                ValidationTimeStamp validation = new ValidationTimeStamp(tsaUrl);
                signedData = validation.addSignedTimeStamp(signedData);

            }
            System.out.println("signed data is ");
            System.out.println(signedData.toString());
            System.out.println(signedData.getSignedContent().toString());
            System.out.println(signedData.toASN1Structure());
            System.out.println(signedData.getSignedContentTypeOID());
            SignerInformation si = (SignerInformation) signedData.getSignerInfos().getSigners().toArray()[0];
            System.out.println("Printing the signature");
            System.out.println("==================================");
            System.out.println(si.getSID());
            System.out.println(new String(si.getSignature()));
            System.out.println(bytesToHex(si.getSignature()));
            System.out.println(signedData.getCertificates());
            System.out.println(signedData.getDigestAlgorithmIDs());
            System.out.println(getSignerInfo(signedData));
            System.out.println(getSignature(signedData));
            System.out.println(getMessage(signedData));
            System.out.println("==================================");
            System.out.println("==================================");
            System.out.println("==================================");

            System.out.println(signedData.getSignerInfos());
            System.out.println(signedData.getSignerInfos().size());
            System.out.println(signedData.getSignerInfos().getSigners().stream().findFirst());
            System.out.println(signedData.getSignedContent().getContent());
            return signedData.getEncoded();
        }
        catch (Exception e)
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
    public CMSProcessableInputStream stringToCMSProcessableInputStream(String inputString) {
        try {
            // Convert the String to an InputStream
            ByteArrayInputStream inputStream = new ByteArrayInputStream(inputString.getBytes("UTF-8"));

            // Wrap the InputStream with CMSProcessableInputStream
            CMSProcessableInputStream cmsInputStream = new CMSProcessableInputStream(inputStream);

            return cmsInputStream;
        } catch (UnsupportedEncodingException e) {
            // Handle the exception, e.g., by throwing or logging it
            e.printStackTrace();
            return null;
        }
    }
    public String bytesToHex(byte[] byteArray) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : byteArray) {
            // Convert the byte to a 2-character hexadecimal representation
            String hex = String.format("%02X", b);
            hexString.append(hex);
        }
        return hexString.toString();
    }
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
    public String getSignerInfo(CMSSignedData signedData){
        SignerInformationStore signerInfos = signedData.getSignerInfos();
        System.out.println("Total signers: "+signerInfos.getSigners().size());
        for (SignerInformation signerInfo : signerInfos.getSigners()) {
            System.out.println("Signer Identity:");
            System.out.println(signerInfo.getSID().getIssuer());
            System.out.println(signerInfo.getSID().getSerialNumber());
            return signerInfo.getSID().toString();
        }
        return null;
    }
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
}