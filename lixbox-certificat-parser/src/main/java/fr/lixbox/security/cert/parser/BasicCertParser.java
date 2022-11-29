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
package fr.lixbox.security.cert.parser;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;

import fr.lixbox.security.cert.model.enumeration.X509Extensions;

/**
 * Cette classe assure la lecture de tout type de certificat.
 * 
 * @author ludovic.terral
 */
public final class BasicCertParser implements CertParser
{
    private static final String SERIAL_NUMBER = "serialNumber";
    // ----------- Attribut -----------
    private static final Log LOG = LogFactory.getLog(BasicCertParser.class);    
    private X509Certificate cert;
    private Map<String, Object> certDatas;



    // ----------- Methode -----------
    public BasicCertParser()
    {
        this.certDatas=new HashMap<>(); 
    }
    public BasicCertParser(X509Certificate cert)
    {
        this.setCert(cert);
        this.certDatas=new HashMap<>(); 
    }



    public void setCert(X509Certificate cert)
    {
        this.cert = cert;
        parse(cert.getSubjectDN());
    }


    @Override
    public X509Certificate getCertificate()
    {
        return cert;
    }
    

    
    @Override
    public Map<String, Object> getCertificateDatas()
    {
        return certDatas;
    }



    @Override
    public String getCertificateId()
    {
        if (!getCertificatRevoque())
        {
            return (String) certDatas.get("othername");
        }
        else
        {
            LOG.debug("Le Certificat n : " +certDatas.get(SERIAL_NUMBER) + " est revoque");
        }
        return null;
    }



    /**
     * Cette methode va veririfier la crl afin de savoir si le certificat est
     * valiede ou revoque.
     */
    public boolean getCertificatRevoque()
    {
        boolean result = true;
        String sCrl = extraireCrlDistributionPoint();
        try(
            InputStream inCrl = new FileInputStream(sCrl);
        )        
        {
         
            CertificateFactory cf;
            cf = CertificateFactory.getInstance("X.509");
            X509CRL crl;
            crl = (X509CRL) cf.generateCRL(inCrl);
            LOG.debug("La CRL courante a ete publie le: " + crl.getThisUpdate());
            LOG.debug("La CRL sera misea jour au plus tard le " + crl.getNextUpdate());
            LOG.debug("La CRL est genene par " + crl.getIssuerDN());
            X509CRLEntry certRevoque = crl.getRevokedCertificate((BigInteger) certDatas.get(SERIAL_NUMBER));
            if (crl.getNextUpdate().before(new Date()))
            {
                LOG.error("LA CRL est expiré");
            }
            if (certRevoque != null)
            {
                result = true;
                LOG.debug("Le CERTIFICAT " + ((BigInteger)certDatas.get(SERIAL_NUMBER)).toString(16) + " est revoque depuis le : "
                        + certRevoque.getRevocationDate());
            }
            else
            {
                result = false;
                LOG.debug("Le CERTIFICAT " + ((BigInteger)certDatas.get(SERIAL_NUMBER)).toString(16) + " est OK, et NON revoque");
            }
        }
        catch (IOException | CertificateException | CRLException e)
        {
            LOG.fatal(e);
        }
        return result;
    }



    /**
     * Cette methode extrait les informations du subjectName resultant de
     * l'analyse du certificat pour extraire les valeurs {OUPAM; OTHERNAME;
     * POLICY; SNUMBER; DISTIBUTIONPCRL; CERTIFICATREVOQUE}
     * 
     * @param subjectDN
     */
    private void parse(Principal subjectDN)
    {
        String info = subjectDN.getName();
        this.certDatas.put("cn", extraireChamp("CN", info));
        this.certDatas.put("c", extraireChamp("C", info));
        this.certDatas.put("l", extraireChamp("L", info));
        this.certDatas.put("o", extraireChamp("O", info));
        this.certDatas.put("ou", extraireChamp("OU", info));
        this.certDatas.put("st", extraireChamp("ST", info));
        this.certDatas.put("policy", extrairePolicy());
        this.certDatas.put(SERIAL_NUMBER, extraireSerialNumber());
        this.certDatas.put("crlDistributionPoints", extraireCrlDistributionPoint());
        this.certDatas.put("othername", extraireOtherName());
    }



    /**
     * Cette methode renvoie la POLICY du certificat
     * 
     * @return la policy
     */
    private String extrairePolicy()
    {
        String policy="";
        byte[] extvalue = cert.getExtensionValue(X509Extensions.CertificatePolicies);
        if (extvalue != null)
        {
            DEROctetString oct;
            ASN1Sequence seq;
            try
            {
                ASN1InputStream asn1InputStream = new ASN1InputStream(
                        new ByteArrayInputStream(extvalue));
                oct = (DEROctetString) (asn1InputStream.readObject());
                ASN1InputStream asn1InputStream2 = new ASN1InputStream(
                        new ByteArrayInputStream(oct.getOctets()));
                seq = (ASN1Sequence) asn1InputStream2.readObject();
                asn1InputStream.close();
                asn1InputStream2.close();
                PolicyInformation pol = new PolicyInformation(
                        (ASN1ObjectIdentifier) ((DLSequence) seq.getObjectAt(0)).getObjectAt(0));
                policy = pol.getPolicyIdentifier().getId();
            }
            catch (IOException e)
            {
                LOG.error(e);
            }
        }
        LOG.debug("POLICY : " + policy);
        return policy;
    }



    /**
     * Cette methode renvoie le numero de serie du certificat
     */
    private BigInteger extraireSerialNumber()
    {
        return cert.getSerialNumber();
    }



    /**
     * Cette methode renvoie le point de distrubtion CRL contenu dans le
     * certificat
     */
    private String extraireCrlDistributionPoint()
    {
        String distribPoint = "";
        byte[] crldpExt = cert.getExtensionValue(X509Extensions.CRLDistributionPoints);
        if (crldpExt != null)
        {
            try
            {
                ASN1InputStream oAsnInStream = new ASN1InputStream(
                        new ByteArrayInputStream(crldpExt));
                ASN1InputStream oAsnInStream2 = null;
                ASN1Primitive derObjCrlDP;
                derObjCrlDP = oAsnInStream.readObject();
                DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
                byte[] crldpExtOctets = dosCrlDP.getOctets();
                oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
                ASN1Primitive derObj2 = oAsnInStream2.readObject();
                CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
                for (DistributionPoint dp : distPoint.getDistributionPoints())
                {
                    DistributionPointName dpn = dp.getDistributionPoint();
                    // Look for URIs in fullName
                    if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
                    {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        // Look for an URI
                        for (int j = 0; j < genNames.length; j++)
                        {
                            if (genNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
                            {
                                String url = ASN1IA5String.getInstance(genNames[j].getName())
                                        .getString();
                                distribPoint = url;
                            }
                        }
                    }
                }
                oAsnInStream.close();
                oAsnInStream2.close();
            }
            catch (IOException e)
            {
                LOG.error(e);
            }
        }
        return distribPoint;
    }



    private List<String> extraireOtherName()
    {
        List<String> identities = new ArrayList<>();
        try
        {
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            // Check that the certificate includes the SubjectAltName extension
            if (altNames == null)
            {
                return Collections.emptyList();
            }
            // Use the type OtherName to search for the certified server name
            for (List<?> item : altNames)
            {
                Integer type = (Integer) item.get(0);
                if (type == 0)
                {
                    // Type OtherName found so return the associated value
                    try
                    (
                        ASN1InputStream decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                    )
                    {
                        ASN1Encodable encoded = decoder.readObject();
                        encoded = ((DLSequence) encoded).getObjectAt(1);
                        encoded = ((DERTaggedObject) encoded).toASN1Primitive();
                        encoded = ((DERTaggedObject) encoded).toASN1Primitive();
                        String identity = ((DERUTF8String) encoded).getString();
                        identities.add(identity);
                    }
                    catch (Exception e)
                    {
                        LOG.error("Error decoding subjectAltName", e);
                    }
                }
            }
        }
        catch (CertificateParsingException e)
        {
            LOG.error("Error parsing SubjectAltName in certificate: ", e);
        }
        return identities;
    }



    /**
     * Cette methode assure la lecture des composantes du subjectName
     * 
     * @param nomChamp
     *            nom du champ recherche
     * @param subjectName
     *            contenu extrait du certificat
     * 
     * @return la valeur du champ
     */
    private String extraireChamp(String nomChamp, String subjectName)
    {
        StringBuilder value = new StringBuilder();
        String keyword = nomChamp + "=";
        int index = subjectName.indexOf(keyword);
        String str = subjectName.substring(index + nomChamp.length() + 1);
        int icou = 0;
        boolean end = (index == -1);
        while ((icou < str.length()) && !end)
        {
            char carcou = str.charAt(icou);
            if (carcou != ',')
            {
                value.append(carcou);
            }
            else
            {
                end = true;
            }
            icou++;
        }
        LOG.debug(keyword + value);
        return value.toString();
    }
}