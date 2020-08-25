/*******************************************************************************
 *    
 *                           FRAMEWORK Lixbox
 *                          ==================
 *      
 *    This file is part of lixbox-security.
 *
 *    lixbox-security is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    lixbox-security is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *    along with lixbox-security.  If not, see <https://www.gnu.org/licenses/>
 *   
 *   @AUTHOR Lixbox-team
 *
 ******************************************************************************/
package fr.lixbox.security.cert.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import fr.lixbox.common.stream.util.StreamStringUtil;
import fr.lixbox.security.cert.model.enumeration.TypeKs;

/**
 * Cette classe est un utilitaire qui fonctionne de facon semblable au keytool
 * 
 * @author ludovic.terral
 */
public class CertificateUtil
{
    // ---------------- Attributs -----------------------    
    private static Pattern valuesPattern = Pattern.compile("(?i)(=)([^,]*)");
    private static final int CERT_REQ_LINE_LENGTH = 76;
    private static final int KEY_SIZE = 2048;
    
    private static Provider provider = new BouncyCastleProvider();
    
    static 
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    

    // ---------------- Methodes -----------------------
    /**
     * Cette methode initialise un keystore type
     * 
     * @param typeKs
     * @param pathKeystore
     * @param pwdeystore
     * 
     * @return le keystore
     * 
     * @return un keystore nouveau ou l'existant
     */
    public static KeyStore initialiseKeyStore(TypeKs typeKs, String pathKeystore, 
            String pwdKeystore)
    {
        KeyStore ks = null;
        File ksFile = new File(pathKeystore);
        FileInputStream fis=null;
        try 
        {
            ks = KeyStore.getInstance(typeKs.getLibelleCourt());            
            if (ksFile.exists())
            {
                fis = new FileInputStream(ksFile);
                ks.load(fis, pwdKeystore.toCharArray());
            }
            else
            {
                ks.load(null);
            }
            saveKeystore(ks, pathKeystore, pwdKeystore);
            if (fis!=null)
            {
                fis.close();
            }
        } 
        catch (Exception e) 
        {
            e.printStackTrace();
        }
        return ks;
    }
    
    
    
    /**
     * Cette methode cree un X509 utilisant le RSA algorithm. La cle privee est
     * stockee dans le keystore passe en parametre
     * 
     * @param ks
     * @param ksPassword
     * @param aliasCert nom utilise pour stocker le certificat dans le keystore.
     * @param issuerDN Issuer string e.g "O=Grid,OU=OGSA,CN=ACME"
     * @param subjectDN Subject string e.g "O=Grid,OU=OGSA,CN=John Doe"
     * @param policyId 
     * @param certRoles
     * @param gpmmRacine
     * @param emailSubject
     * 
     * @return un X509 V3 Certificate.
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws OperatorCreationException 
     */
    public static X509Certificate createRSACert(KeyStore ks, String ksPassword, String alias, String issuerDN,
            String subjectDN, String policy, KeyPurposeId[] certRoles, X509Certificate gpmmRacine,
            String emailSubject) 
        throws GeneralSecurityException, IOException, OperatorCreationException
    {
        // Generate public and private keys
        KeyPair keyPair = generateKeyPair("RSA", KEY_SIZE);
        
        // Create X509 certificate with keys and specified otherName
        X509Certificate cert = createX509V3Certificate(keyPair, 60, issuerDN, subjectDN, "SHA256withRSA", policy, 
                certRoles, gpmmRacine, emailSubject);
        
        // Store new certificate and private key in the keystore
        ks.setKeyEntry(alias, keyPair.getPrivate(), ksPassword.toCharArray(), new X509Certificate[] { cert });

        // Return new certificate
        return cert;
    }



    /**
     * Cette methode supprimer un certificat du ks
     * 
     * @param ks
     * @param alias
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static void deleteCertificate(KeyStore ks, String alias) throws GeneralSecurityException, IOException
    {
        ks.deleteEntry(alias);
    }



    /**
     * Cette methode recupere un certificat du ks via l'alias
     * 
     * @param ks
     * @param alias
     * @return 
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static Certificate getCertificate(KeyStore ks, String alias) throws GeneralSecurityException, IOException
    {
        return ks.getCertificate(alias);
    }
    


    /**
     * Cette methode renvoie true si le certifat est de type RSA
     * 
     * @param certificate 
     * 
     * @return true if the specified certificate is using the RSA algorithm.
     * 
     * @throws KeyStoreException
     */
    public static boolean isRSACertificate(X509Certificate certificate) throws KeyStoreException
    {
        return certificate.getPublicKey().getAlgorithm().equals("RSA");
    }

    

    /**
     * Cette methode renvoie true si le certificat est un auto-signe.
     * 
     * @param ks
     * @param alias
     * 
     * @return true if the specified certificate is a self-signed certificate.
     * 
     * @throws KeyStoreException
     */
    public static boolean isSelfSignedCertificate(KeyStore ks, String alias) throws KeyStoreException
    {
        // Get certificate chain
        java.security.cert.Certificate[] certificateChain = ks.getCertificateChain(alias);
        
        // Verify that the chain is empty or was signed by himself
        return certificateChain == null || certificateChain.length == 1;
    }



    /**
     * Cette methode renvoie true si le certificat est en attente d'une reponse
     * de l'autorite de certification.
     * 
     * @param keyStore
     * @param alias
     * 
     * @return true if the specified certificate is ready to be signed by a
     *         Certificate Authority.
     *         
     * @throws KeyStoreException
     */
    public static boolean isSigningRequestPending(KeyStore keyStore, String alias) throws KeyStoreException
    {
        // Verify that this is a self-signed certificate
        if (!isSelfSignedCertificate(keyStore, alias))
        {
            return false;
        }
        // Verify that the issuer information has been entered
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        Matcher matcher = valuesPattern.matcher(certificate.getIssuerDN().toString());
        return matcher.find() && matcher.find();
    }



    /**
     * Cette methode genere le contenu d'une demande de signature de certificats (CSR).
     * 
     * @param cert the certificate to create a signing request.
     * @param privKey the private key of the certificate.
     * 
     * @return the content of a new singing request for the specified certificate.
     * 
     * @throws SignatureException 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws IOException 
     * @throws OperatorCreationException 
     */
    public static String createSigningRequest(X509Certificate cert, PrivateKey privKey) 
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException
    {
        String subject = cert.getSubjectDN().getName();
        X500Principal xname = new X500Principal(subject);
        PublicKey pubKey = cert.getPublicKey();
        String signatureAlgorithm = cert.getSigAlgName();
        
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                xname, pubKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        ContentSigner signer = csBuilder.build(privKey);
        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = p10Builder.build(signer);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        ASN1OutputStream deros = ASN1OutputStream.create(baos);
        deros.writeObject(csr.toASN1Structure());
        String sTmp = new String(org.bouncycastle.util.encoders.Base64.encode(baos.toByteArray()),StandardCharsets.UTF_8);
        deros.close();
        baos.close();
        
        // Header
        StringBuffer sb = new StringBuffer(60);
        sb.append("-----BEGIN NEW CERTIFICATE REQUEST-----\n");
        // Add signing request content (base 64 encoded)
        for (int iCnt = 0; iCnt < sTmp.length(); iCnt += CERT_REQ_LINE_LENGTH)
        {
            int iLineLength;
            if ((iCnt + CERT_REQ_LINE_LENGTH) > sTmp.length())
            {
                iLineLength = sTmp.length() - iCnt;
            }
            else
            {
                iLineLength = CERT_REQ_LINE_LENGTH;
            }
            sb.append(sTmp.substring(iCnt, iCnt + iLineLength)).append("\n");
        }
        // Footer
        sb.append("-----END NEW CERTIFICATE REQUEST-----\n");
        return sb.toString();
    }



    /**
     * Cette methode integre la reponse de l'autorite de certification au keystore
     * et chaine alors le certificat.
     * 
     * @param keyStore
     * @param trustStore
     * @param ksPassword
     * @param alias
     * @param inputStream the stream containing the CA reply.
     * @param trustCACerts true if certificates present in the truststore file will be
     *            used to verify the identity of the entity signing the
     *            certificate.
     * @param validateRoot
     *            true if you want to verify that the root certificate in the
     *            chain can be trusted based on the truststore.
     *            
     * @return true if the CA reply was successfully processed.
     * 
     * @throws Exception
     */
    public static boolean installReply(KeyStore keyStore, KeyStore trustStore, String ksPassword, String alias,
            InputStream inputStream, boolean trustCACerts, boolean validateRoot) throws Exception
    {
        // Check that there is a certificate for the specified alias
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        if (certificate == null)
        {
            return false;
        }
        
        // Retrieve the private key of the stored certificate
        PrivateKey privKey = (PrivateKey) keyStore.getKey(alias, ksPassword.toCharArray());
        
        // Load certificates found in the PEM input stream
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (Certificate cert : CertificateFactory.getInstance("X509").generateCertificates(inputStream))
        {
            certs.add((X509Certificate) cert);
        }
        if (certs.isEmpty())
        {
            throw new Exception("Reply has no certificates");
        }
        List<X509Certificate> newCerts;
        if (certs.size() == 1)
        {
            // Reply has only one certificate
            newCerts = establishCertChain(keyStore, trustStore, null, certs.get(0), trustCACerts);
        }
        else
        {
            // Reply has a chain of certificates
            newCerts = validateReply(keyStore, trustStore, alias, null, certs, trustCACerts, validateRoot);
        }
        if (newCerts != null)
        {
            keyStore.setKeyEntry(alias, privKey, ksPassword.toCharArray(), newCerts.toArray(new X509Certificate[newCerts.size()]));
            return true;
        }
        else
        {
            return false;
        }
    }

    
    
    /**
     * Cette methode importe un certificat sans cle privee dans le keystore.
     * 
     * @param keyStore
     * @param ksPassword
     * @param alias 
     * @param inputStream the stream containing the signed certificate. 
     *            
     * @return true if the certificate was successfully imported.
     * 
     * @throws Exception
     */
    public static boolean importCert(KeyStore keyStore, final String ksPassword, String alias, 
        InputStream inputStream) throws Exception
    {
        // Check that there is a certificate for the specified alias
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        if (certificate != null)
        {
            return false;
        }
                      
        // Load certificates found in the PEM input stream
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (Certificate cert : CertificateFactory.getInstance("X509").generateCertificates(inputStream))
        {
            certs.add((X509Certificate) cert);
        }
        if (certs.isEmpty())
        {
            throw new Exception("No certificates were found");
        }
        keyStore.setCertificateEntry(alias, certs.get(0));
        return true;
    }

    
    
    /**
     * Cette methode importe un certificat sans cle privee dans le keystore.
     * 
     * @param keyStore
     * @param ksPassword
     * @param alias 
     * @param inputStream the stream containing the signed certificate. 
     *            
     * @return true if the certificate was successfully imported.
     * 
     * @throws Exception
     */
    public static boolean importCert(KeyStore keyStore, final String ksPassword, String[] alias, 
            InputStream[] inputStream) throws Exception
    {
        // Check that there is a certificate for the specified alias
        for (String tmp: alias)
        {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(tmp);
            if (certificate != null)
            {
                return false;
            }
        }
                      
        // Load certificates found in the PEM input stream
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        for (InputStream is: inputStream)
        {
            for (Certificate cert : CertificateFactory.getInstance("X509").generateCertificates(is))
            {
                certs.add((X509Certificate) cert);
            }
        }
        if (certs.isEmpty())
        {
            throw new Exception("No certificates were found");
        }
        int i=0;
        for (String tmp: alias)
        {
            keyStore.setCertificateEntry(tmp, certs.get(i));
            i++;
        }
        return true;
    }
    


    /**
     * Cette methode importe un certificat signe avec sa cle privee dans le keystore.
     * 
     * @param keyStore
     * @param trustStore
     * @param ksPassword
     * @param alias
     * @param pkInputStream the stream containing the private key.
     * @param passPhrase is the password phrased used when creating the private key.
     * @param inputStream the stream containing the signed certificate.
     * @param trustCACerts
     *            true if certificates present in the truststore file will be
     *            used to verify the identity of the entity signing the
     *            certificate.
     * @param typeConteneur            
     * @param validateRoot
     *            true if you want to verify that the root certificate in the
     *            chain can be trusted based on the truststore.
     *            
     * @return true if the certificate was successfully imported.
     * 
     * @throws Exception
     */
    public static boolean importCert(KeyStore keyStore, KeyStore trustStore, String ksPassword, String alias,
            InputStream pkInputStream, final String passPhrase, InputStream inputStream, boolean trustCACerts,
            boolean validateRoot, TypeKs typeKs) throws Exception
    {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privKey = null;
        if (certificate != null)
        {
            return false;
        }
        
        switch (typeKs)
        {
            case PKCS12:
                KeyStore ks = KeyStore.getInstance("pkcs12");
                ks.load(pkInputStream, passPhrase.toCharArray());
                privKey = (PrivateKey)ks.getKey(alias, passPhrase.toCharArray());
                certs.add((X509Certificate) ks.getCertificate(alias));
                break;
            default:
                break;
        }

        
        // Load certificates found in the PEM input stream
        if (certs.isEmpty())
        {
            throw new Exception("No certificates were found");
        }
        List<X509Certificate> newCerts;
        if (certs.size() == 1)
        {
            // Reply has only one certificate
            newCerts = establishCertChain(keyStore, trustStore, null, certs.get(0), trustCACerts);
        }
        else
        {
            // Reply has a chain of certificates
            newCerts = validateReply(keyStore, trustStore, alias, null, certs, trustCACerts, validateRoot);
        }
        if (newCerts != null)
        {
            keyStore.setKeyEntry(alias, privKey, ksPassword.toCharArray(), newCerts.toArray(new X509Certificate[newCerts.size()]));
            return true;
        }
        else
        {
            return false;
        }
    }


    
    /**
     * Cette methode sauvegarde le keystore.
     *   
     * @param ks
     * @param pathKeystore
     * @param pwdKeystore
     * 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     */
    public static void saveKeystore(KeyStore ks, String pathKeystore, String pwdKeystore) 
        throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        File keyStoreFile= new File(pathKeystore);
        final FileOutputStream fos = new FileOutputStream(keyStoreFile);
        ks.store(fos, pwdKeystore.toCharArray());
        fos.close();
    }



    /**
     * Cette methode renvoie la cle privee d'un certificat
     * 
     * @param ks
     * @param alias
     * @param passPhrase
     * 
     * @return la cle privee
     * 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     */
    public static Key getPrivateKey(KeyStore ks, String alias, String passPhrase) 
        throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
    {
        return ks.getKey(alias, passPhrase.toCharArray());
    }



    /**
     * Cette methode genere et enregistre la csr dans un fichier.
     * 
     * @param cert
     * @param privKey
     * @param pathCsr 
     * 
     * @throws IOException 
     * @throws SignatureException 
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws OperatorCreationException 
     */
    public static void createWriteSigningRequest(X509Certificate cert, PrivateKey privKey, OutputStream pathCsr) 
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException
    {
        String csr = createSigningRequest(cert, privKey);
        StreamStringUtil.write(csr, pathCsr);
    }
        
    

    private static List<X509Certificate> establishCertChain(KeyStore keyStore, KeyStore trustStore, X509Certificate certificate,
            X509Certificate certReply, boolean trustCACerts) throws Exception
    {
        if (certificate != null)
        {
            PublicKey publickey = certificate.getPublicKey();
            PublicKey publickey1 = certReply.getPublicKey();
            if (!publickey.equals(publickey1))
            {
                throw new Exception("Public keys in reply and keystore don't match");
            }
            if (certReply.equals(certificate))
            {
                throw new Exception("Certificate reply and certificate in keystore are identical");
            }
        }
        Map<Principal, List<X509Certificate>> knownCerts = new Hashtable<Principal, List<X509Certificate>>();
        if (keyStore.size() > 0)
        {
            knownCerts.putAll(getCertsByIssuer(keyStore));
        }
        if (trustCACerts && trustStore.size() > 0)
        {
            knownCerts.putAll(getCertsByIssuer(trustStore));
        }
        LinkedList<X509Certificate> answer = new LinkedList<X509Certificate>();
        if (buildChain(certReply, answer, knownCerts))
        {
            return answer;
        }
        else
        {
            throw new Exception("Failed to establish chain from reply");
        }
    }



    /**
     * Cette methode construit une chaine de certificat.
     * 
     * @param certificate
     * @param answer the certificate chain for the corresponding certificate.
     * @param knownCerts
     *            list of known certificates grouped by their issues (i.e.
     *            Principals).
     *            
     * @return true if the entire chain of all certificates was successfully
     *         built.
     */
    private static boolean buildChain(X509Certificate certificate, LinkedList<X509Certificate> answer,
            Map<Principal, List<X509Certificate>> knownCerts)
    {
        Principal subject = certificate.getSubjectDN();
        Principal issuer = certificate.getIssuerDN();
        
        // Check if the certificate is a root certificate (i.e. was issued by
        // the same Principal that
        // is present in the subject)
        if (subject.equals(issuer))
        {
            answer.addFirst(certificate);
            return true;
        }
        
        // Get the list of known certificates of the certificate's issuer
        List<X509Certificate> issuerCerts = knownCerts.get(issuer);
        if (issuerCerts == null || issuerCerts.isEmpty())
        {
            // No certificates were found so building of chain failed
            return false;
        }
        
        for (X509Certificate issuerCert : issuerCerts)
        {
            PublicKey publickey = issuerCert.getPublicKey();
            try
            {
                // Verify the certificate with the specified public key
                certificate.verify(publickey);
                // Certificate was verified successfully so build chain of
                // issuer's certificate
                if (!buildChain(issuerCert, answer, knownCerts))
                {
                    return false;
                }
            }
            catch (Exception exception)
            {
                // Failed to verify certificate
                return false;
            }
        }
        answer.addFirst(certificate);
        return true;
    }



    /**
     * Cette methode renvoie une Map qui conteint les certificate issuers and values de certificates.
     * 
     * @param ks
     * 
     * @return a map with the certificates per issuer.
     * @throws Exception
     */
    private static Map<Principal, List<X509Certificate>> getCertsByIssuer(KeyStore ks) throws Exception
    {
        Map<Principal, List<X509Certificate>> answer = new HashMap<Principal, List<X509Certificate>>();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if (cert != null)
            {
                Principal subjectDN = cert.getSubjectDN();
                List<X509Certificate> vec = answer.get(subjectDN);
                if (vec == null)
                {
                    vec = new ArrayList<X509Certificate>();
                    vec.add(cert);
                }
                else
                {
                    if (!vec.contains(cert))
                    {
                        vec.add(cert);
                    }
                }
                answer.put(subjectDN, vec);
            }
        }
        return answer;
    }



    /**
     * Cette methode verifie la certification reply, et renvoie la liste ordonnee
     * de la chaine
     * 
     * @param alias
     * @param userCert
     * @param replyCerts
     */
    private static List<X509Certificate> validateReply(KeyStore keyStore, KeyStore trustStore, String alias,
            X509Certificate userCert, List<X509Certificate> replyCerts, boolean trustCACerts, boolean verifyRoot)
            throws Exception
    {
        // order the certs in the reply (bottom-up).
        int i;
        X509Certificate tmpCert;
        if (userCert != null)
        {
            PublicKey userPubKey = userCert.getPublicKey();
            for (i = 0; i < replyCerts.size(); i++)
            {
                if (userPubKey.equals(replyCerts.get(i).getPublicKey()))
                {
                    break;
                }
            }
            if (i == replyCerts.size())
            {
                throw new Exception("Certificate reply does not contain public key for <alias>: " + alias);
            }
            tmpCert = replyCerts.get(0);
            replyCerts.set(0, replyCerts.get(i));
            replyCerts.set(i, tmpCert);
        }
        Principal issuer = replyCerts.get(0).getIssuerDN();
        for (i = 1; i < replyCerts.size() - 1; i++)
        {
            // find a cert in the reply whose "subject" is the same as the
            // given "issuer"
            int j;
            for (j = i; j < replyCerts.size(); j++)
            {
                Principal subject = replyCerts.get(j).getSubjectDN();
                if (subject.equals(issuer))
                {
                    tmpCert = replyCerts.get(i);
                    replyCerts.set(i, replyCerts.get(j));
                    replyCerts.set(j, tmpCert);
                    issuer = replyCerts.get(i).getIssuerDN();
                    break;
                }
            }
            if (j == replyCerts.size())
            {
                throw new Exception("Incomplete certificate chain in reply");
            }
        }
        // now verify each cert in the ordered chain
        for (i = 0; i < replyCerts.size() - 1; i++)
        {
            PublicKey pubKey = replyCerts.get(i + 1).getPublicKey();
            try
            {
                replyCerts.get(i).verify(pubKey);
            }
            catch (Exception e)
            {
                throw new Exception("Certificate chain in reply does not verify: " + e.getMessage());
            }
        }
        if (!verifyRoot)
        {
            return replyCerts;
        }
        // do we trust the (root) cert at the top?
        X509Certificate topCert = replyCerts.get(replyCerts.size() - 1);
        boolean foundInKeyStore = keyStore.getCertificateAlias(topCert) != null;
        boolean foundInCAStore = trustCACerts && (trustStore.getCertificateAlias(topCert) != null);
        if (!foundInKeyStore && !foundInCAStore)
        {
            boolean verified = false;
            X509Certificate rootCert = null;
            if (trustCACerts)
            {
                for (Enumeration<String> aliases = trustStore.aliases(); aliases.hasMoreElements();)
                {
                    String name = aliases.nextElement();
                    rootCert = (X509Certificate) trustStore.getCertificate(name);
                    if (rootCert != null)
                    {
                        try
                        {
                            topCert.verify(rootCert.getPublicKey());
                            verified = true;
                            break;
                        }
                        catch (Exception e)
                        {
                            // Ignore
                        }
                    }
                }
            }
            if (!verified)
            {
                return null;
            }
            else
            {
                // Check if the cert is a self-signed cert
                if (!topCert.getSubjectDN().equals(topCert.getIssuerDN()))
                {
                    // append the (self-signed) root CA cert to the chain
                    replyCerts.add(rootCert);
                }
            }
        }
        return replyCerts;
    }



    /**
     * Cette methode cree un certificat un X509 version3.
     * 
     * @param kp KeyPair
     * @param months time to live
     * @param issuerDN Issuer string e.g "O=Grid,OU=OGSA,CN=ACME"
     * @param subjectDN  Subject string e.g "O=Grid,OU=OGSA,CN=John Doe"
     * @param signAlgoritm Signature algorithm. This can be either a name or an OID.
     * @param policy
     * @param certRoles
     * @param acGpmm
     * @param emailSubject
     * 
     * @return X509 V3 Certificate
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws OperatorCreationException 
     */
    @SuppressWarnings("deprecation")
    private static synchronized X509Certificate createX509V3Certificate(KeyPair kp, int months, String issuerDN,
            String subjectDN, String signAlgoritm, String policy, KeyPurposeId[] certRoles, X509Certificate acGpmm,
            String emailSubject) throws GeneralSecurityException, IOException, OperatorCreationException
    {
        PublicKey pubKey = kp.getPublic();
        PrivateKey privKey = kp.getPrivate();
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed((new Date().getTime()));
        random.nextBytes(serno);
        BigInteger serial = (new java.math.BigInteger(serno)).abs();
        DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);
        
        
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date endDate = new Date(System.currentTimeMillis() + months * (1000L * 60 * 60 * 24 * 30));
        
        X509v3CertificateBuilder certGenerator = new JcaX509v3CertificateBuilder(
                new X500Name(issuerDN), serial, startDate, endDate, new X500Name(subjectDN), pubKey);
       
                
        // Traitement des basics constraints
        BasicConstraints bc = new BasicConstraints(false);
        certGenerator.addExtension(Extension.basicConstraints, true, bc);
        
        // Traitement de la policy
        if (policy != null)
        {
            PolicyInformation pi = new PolicyInformation(new ASN1ObjectIdentifier(policy));
            DERSequence seq = new DERSequence(pi);
            certGenerator.addExtension(Extension.certificatePolicies, false, seq);
        }
       
        // Traitement des extensions
        certGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment));
        if (certRoles != null)
        {
            Vector<KeyPurposeId> vroles = new Vector<KeyPurposeId>();
            Collections.addAll(vroles, certRoles);
            ExtendedKeyUsage eku = new ExtendedKeyUsage(vroles.toArray(new KeyPurposeId[0]));
            certGenerator.addExtension(Extension.extendedKeyUsage, true, eku);
        }
        
        // Traitement des extensions de certificat NETSCAPE
        certGenerator.addExtension(MiscObjectIdentifiers.netscapeCertType, false, new NetscapeCertType(NetscapeCertType.sslServer
                | NetscapeCertType.smime));
        
        // Traitement de la cle de l'autorite extension.
        SubjectPublicKeyInfo issuePubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(acGpmm.getPublicKey().getEncoded()));
        certGenerator.addExtension(Extension.authorityKeyIdentifier, false, x509ExtensionUtils.createAuthorityKeyIdentifier(issuePubKeyInfo));
        
        // Traitement du subject alternative-name extension (critical).        
        GeneralName email = null; 
        email = new GeneralName(GeneralName.rfc822Name, emailSubject);
        GeneralNamesBuilder builder = new GeneralNamesBuilder();
        builder.addName(email);
        GeneralNames subjectAltName = builder.build();
        certGenerator.addExtension(new ASN1ObjectIdentifier("2.5.29.17"), false, subjectAltName);
        
        
        //Traitement de l'identifiant de cle du sujet
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(pubKey.getEncoded()));
        certGenerator.addExtension(Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));
        
        
        // Generate Certificate
        ContentSigner sigGen = new JcaContentSignerBuilder(signAlgoritm).setProvider("BC").build(privKey);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGenerator.build(sigGen));
        
        cert.checkValidity(new Date());
        cert.verify(pubKey);
        return cert;
    }



    /**
     * Cette methode renvoie a public & private key with the specified algorithm
     * 
     * @param algorithm RSA, etc.
     * @param keysize
     * 
     * @return a new public & private key with the specified algorithm
     * 
     * @throws GeneralSecurityException
     */
    private static KeyPair generateKeyPair(String algorithm, int keysize) throws GeneralSecurityException
    {
        KeyPairGenerator generator;
        if (provider == null)
        {
            generator = KeyPairGenerator.getInstance(algorithm);
        }
        else
        {
            generator = KeyPairGenerator.getInstance(algorithm, provider);
        }
        generator.initialize(keysize, new SecureRandom());
        return generator.generateKeyPair();
    }
}
