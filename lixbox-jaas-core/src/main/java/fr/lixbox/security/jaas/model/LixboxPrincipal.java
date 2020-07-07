/*******************************************************************************
 *    
 *                           FRAMEWORK Lixbox
 *                          ==================
 *      
 * This file is part of lixbox-plugins.
 *
 *    lixbox-security is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    lixbox-supervision is distributed in the hope that it will be useful,
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