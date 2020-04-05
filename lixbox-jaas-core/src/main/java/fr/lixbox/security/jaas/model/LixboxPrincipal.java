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
package fr.lixbox.security.jaas.model;

import java.io.Serializable;
import java.security.Principal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import fr.lixbox.security.jaas.model.enumeration.TypeAuthentification;
import fr.lixbox.security.jaas.model.enumeration.TypeCompte;

/**
 * Cette classe contient le user et son identite.
 * 
 * @author ludovic.terral
 */
public class LixboxPrincipal implements Principal, Serializable
{
    // ----------- Attribut -----------
    public static final long serialVersionUID = 4044757122869505855L;
    protected TypeCompte typeCompte;
    protected TypeAuthentification typeAuthentification;
    protected String name = "";
    protected String certificateId = "";

    
    
    // ----------- Methode -----------
    public LixboxPrincipal(String name)
    {
        super();
        this.setName(name);
    }



    public LixboxPrincipal(String name, String certificatId)
    {
        super();
        this.setName(name);
        this.setCertificateId(certificatId);
    }



    public LixboxPrincipal(String name, TypeAuthentification typeAuthentification)
    {
        super();
        this.setName(name);
        this.setTypeAuthentification(typeAuthentification);
    }



    public LixboxPrincipal()
    {
        super();
    }



    public void setName(String name)
    {
        this.name = name;
    }
    public String getName()
    {
        return name;
    }



    public String getCertificateId()
    {
        return certificateId;
    }
    public void setCertificateId(String certificateId)
    {
        this.certificateId = certificateId;
    }



    public TypeCompte getTypeCompte()
    {
        return typeCompte;
    }
    public void setTypeCompte(TypeCompte typeCompte)
    {
        this.typeCompte = typeCompte;
    }



    public TypeAuthentification getTypeAuthentification()
    {
        return typeAuthentification;
    }
    public void setTypeAuthentification(TypeAuthentification typeAuthentification)
    {
        this.typeAuthentification = typeAuthentification;
    }



    @Override
    public String toString()
    {
        String result = "Content error";
        ObjectMapper mapper = new ObjectMapper();
        try
        {
            result = mapper.writeValueAsString(this);
        }
        catch (JsonProcessingException e)
        {
            e.printStackTrace();
        }
        return result;
    }
}