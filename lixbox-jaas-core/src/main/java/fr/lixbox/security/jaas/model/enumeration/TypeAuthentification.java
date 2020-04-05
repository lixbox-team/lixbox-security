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
package fr.lixbox.security.jaas.model.enumeration;

import javax.xml.bind.annotation.XmlEnum;


/**
 * 
 * Cette classe référence les familles d'authentification
 * 
 * @author ludovic.terral
 */
@XmlEnum
public enum TypeAuthentification
{
    BASIC,
    TOKEN,
    CERTIFICAT,
    LDAP;
}
