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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Cette classe assure l'importation d'un certificat via internet dans un keystore
 * 
 * @author ludovic.terral
 */
public class WebCertificatImporter
{
    // ----------- Attribut -----------   
    private static final Log LOG = LogFactory.getLog(WebCertificatImporter.class);    
    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
    
    private String host;
    private int port=443;
    private String keystorePass;
    private File   keystore;
    private String pathKeystore;

    
    
    // ----------- Methode -----------    
    public WebCertificatImporter(String host, int port, String pathKeystore, String keystorePass)
    {
        this.host=host;
        this.port=port;
        this.keystorePass=keystorePass;
        this.keystore = new File(pathKeystore);
        this.pathKeystore = pathKeystore;
    }
    
    
    
    public WebCertificatImporter(String host, String pathKeystore, String keystorePass)
    {
        this.host=host;
        this.keystorePass=keystorePass;
        this.keystore = new File(pathKeystore);
        this.pathKeystore = pathKeystore;
    }    
    
    
    
    /**
     * Cette methode transforme un tableau d'octets en 
     * une chaine de caractere particuliere
     *       
     * @param bytes
     * 
     * @return une chaine
     */
    private String toHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes)
        {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }
      
    
    
    
    /**
     * Cette methode se connecte a Internet, recupere le ou les certificats 
     * du host contacte. Il ajoute chacun des certificats dans le keystore
     */
    public void integrerCerticatDansKeystore() throws NoSuchAlgorithmException
    {        
        LOG.info("Loading KeyStore " + pathKeystore + "...");
        try
        {
            //charger le keystore
            InputStream in = new FileInputStream(keystore);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(in, keystorePass.toCharArray());
            in.close();
            
            
            //requete sur l'host
            SSLContext context = SSLContext.getInstance("TLS");
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[] { tm }, null);
            SSLSocketFactory factory = context.getSocketFactory();
            LOG.info("Opening connection to " + host + ":" + port + "...");
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);        
            socket.setSoTimeout(10000);
            try
            {
                LOG.info("Starting SSL handshake...");
                socket.startHandshake();
                socket.close();
                LOG.info("No errors, certificate is already trusted");
            }
            catch (SSLException e)
            {
                LOG.error(e,e);
            }
            X509Certificate[] chain = tm.chain;
            if (chain == null)
            {
                LOG.info("Could not obtain server certificate chain");
                return;
            }
            LOG.info("Server sent " + chain.length + " certificate(s):");
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            for (int i = 0; i < chain.length; i++)
            {
                X509Certificate cert = chain[i];
                LOG.info(" " + (i + 1) + " Subject " + cert.getSubjectDN());
                LOG.info("   Issuer  " + cert.getIssuerDN());
                sha1.update(cert.getEncoded());
                LOG.info("   sha1    " + toHexString(sha1.digest()));
                md5.update(cert.getEncoded());
                LOG.info("   md5     " + toHexString(md5.digest()));
                            
                //integration du certificat au keystore        
                String alias = host + "-" + (i + 1);
                ks.setCertificateEntry(alias, cert);
                LOG.info("Certificate added into keystore "+ pathKeystore +" using alias '"+ alias + "'");
            }
     
            
            //enregistrement du keystore
            OutputStream out = new FileOutputStream(keystore);
            ks.store(out, keystorePass.toCharArray());
            out.close();    
        }
        catch(RuntimeException e)
        {
            LOG.error(e);
        }          
        catch(Exception e)
        {
            LOG.error(e);
        }       
    }
    

    
    // ----------- Inner Class ----------- 
    private static class SavingTrustManager implements X509TrustManager
    {
        // ----------- Attribut -----------   
        private final X509TrustManager tm;
        private X509Certificate[] chain;
        

        
        // ----------- Methode -----------  
        SavingTrustManager(X509TrustManager tm)
        {
            this.tm = tm;
        }


        
        public X509Certificate[] getAcceptedIssuers()
        {
            throw new UnsupportedOperationException();
        }

        

        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
        {
            throw new UnsupportedOperationException();
        }


        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
        {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
}
