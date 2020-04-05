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
package fr.lixbox.security.cert.model.enumeration;

import java.io.Serializable;


/**
 *  Cette classe d'enumeration regroupe tous les 
 *  types de keystore.
 *  
 *  @author ludovic.terral  
 */
public enum TypeKs implements Serializable
{
    // ----------- Attribut -----------
    JKS("KEYSTORE SUN JKS","JKS"),     
    PEM("KEYSTORE PEM","PEM"),
    PKCS12("KEYSTORE PKCS12", "PKCS12");
  
    private String libelle;
    private String libelleCourt;

    
    
    // ----------- Methode -----------
    private TypeKs(String libelle, String libelleCourt)
    {
        this.libelle = libelle;
        this.libelleCourt = libelleCourt;
    }
    
    
    
    public String getLibelle()
    {
        return libelle;
    }
    


    public String getLibelleCourt()
    {
        return libelleCourt;
    }

    

    @Override
    public String toString()
    {
        return libelle;
    }
}
