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
