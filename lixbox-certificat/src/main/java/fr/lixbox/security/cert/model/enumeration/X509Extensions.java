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
package fr.lixbox.security.cert.model.enumeration;

/**
 * Cette classe enumere les extensions
 * du certificat X509
 * 
 * @author ludovic.terral
 */
public class X509Extensions
{
    // ----------- Attribut -----------
    public static final String SubjectDirectoryAttributes = "2.5.29.9";
    public static final String SubjectKeyIdentifier = "2.5.29.14";
    public static final String KeyUsage = "2.5.29.15";
    public static final String PrivateKeyUsagePeriod = "2.5.29.16";
    public static final String SubjectAlternativeName = "2.5.29.17";
    public static final String IssuerAlternativeName = "2.5.29.18";
    public static final String BasicConstraints = "2.5.29.19";
    public static final String CRLNumber = "2.5.29.20";
    public static final String ReasonCode = "2.5.29.21";
    public static final String InstructionCode = "2.5.29.23";
    public static final String InvalidityDate = "2.5.29.24";
    public static final String DeltaCRLIndicator = "2.5.29.27";
    public static final String IssuingDistributionPoint = "2.5.29.28";
    public static final String CertificateIssuer = "2.5.29.29";
    public static final String NameConstraints = "2.5.29.30";
    public static final String CRLDistributionPoints = "2.5.29.31";
    public static final String CertificatePolicies = "2.5.29.32";
    public static final String PolicyMappings = "2.5.29.33";
    public static final String AuthorityKeyIdentifier = "2.5.29.35";
    public static final String PolicyConstraints = "2.5.29.36";
    public static final String ExtendedKeyUsage = "2.5.29.37";
    public static final String FreshestCRL = "2.5.29.46";
    public static final String InhibitAnyPolicy = "2.5.29.54";
    public static final String AuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
    public static final String SubjectInfoAccess = "1.3.6.1.5.5.7.1.11";
    public static final String LogoType = "1.3.6.1.5.5.7.1.12";
    public static final String BiometricInfo = "1.3.6.1.5.5.7.1.2";
    public static final String QCStatements = "1.3.6.1.5.5.7.1.3";
    public static final String AuditIdentity = "1.3.6.1.5.5.7.1.4";
    public static final String NoRevAvail = "2.5.29.56";
    public static final String TargetInformation = "2.5.29.55";
}