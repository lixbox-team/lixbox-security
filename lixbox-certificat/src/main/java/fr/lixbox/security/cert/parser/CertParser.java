/*******************************************************************************
 *    
 *                           FRAMEWORK Lixbox
 *                          ==================
 *      
 *   Copyrigth - LIXTEC - Tous droits reserves.
 *   
 *   Le contenu de ce fichier est la propriete de la societe Lixtec.
 *   
 *   Toute utilisation de ce fichier et des informations, sous n'importe quelle
 *   forme necessite un accord ecrit explicite des auteurs
 *   
 *   @AUTHOR Ludovic TERRAL
 *
 ******************************************************************************/
package fr.lixbox.security.cert.parser;

import java.security.cert.X509Certificate;
import java.util.Map;

public interface CertParser
{
    // ----------- Methode -----------
    X509Certificate getCertificate();
    Map<String, Object> getCertificateDatas();
    String getCertificateId();
}