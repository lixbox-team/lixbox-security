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
package fr.lixbox.security.keycloak;

import java.io.Serializable;

import org.keycloak.representations.AccessToken;

/**
 * Ce client fournit un outil de demande de token à keycloak.
 * 
 *  @author ludovic.terral
 */
public class ExtendAccessToken implements Serializable
{
    // ----------- Attribut(s) -----------
    private static final long serialVersionUID = 20200928115212L;
    
    private String rawToken;
    private AccessToken token;
    
    
    
    // ----------- Methode(s) -----------
    public String getRawToken()
    {
        return rawToken;
    }
    public void setRawToken(String rawToken)
    {
        this.rawToken = rawToken;
    }
    
    
    
    public AccessToken getToken()
    {
        return token;
    }
    public void setToken(AccessToken token)
    {
        this.token = token;
    }
}
