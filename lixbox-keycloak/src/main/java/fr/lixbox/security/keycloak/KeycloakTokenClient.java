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

import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;

import fr.lixbox.common.util.StringUtil;

/**
 * Ce client fournit un outil de demande de token à keycloak.
 * 
 *  @author ludovic.terral
 */
public class KeycloakTokenClient
{
    // ----------- Attribut(s) -----------
    private final String serverUrl;
    private final String realmId;
    private final String clientId;
    private final String clientSecret;
    
    
    
    // ----------- Methode(s) -----------
    public KeycloakTokenClient(String serverUrl, String realmId, String clientId)
    {
        this.serverUrl = serverUrl;
        this.realmId = realmId;
        this.clientId = clientId;
        this.clientSecret = null;
    }



    public KeycloakTokenClient(String serverUrl, String realmId, String clientId,
            String clientSecret)
    {
        this.serverUrl = serverUrl;
        this.realmId = realmId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }



    public ExtendAccessToken getAccessToken() throws VerificationException
    {
        return getAccessToken(newKeycloakBuilderWithClientCredentials().build());
    }



    public String getAccessTokenString()
    {
        return getAccessTokenString(newKeycloakBuilderWithClientCredentials().build());
    }



    public ExtendAccessToken getAccessToken(String username, String password) throws VerificationException
    {
        return getAccessToken(
                newKeycloakBuilderWithPasswordCredentials(username, password).build());
    }



    public String getAccessTokenString(String username, String password)
    {
        return getAccessTokenString(
                newKeycloakBuilderWithPasswordCredentials(username, password).build());
    }



    private ExtendAccessToken getAccessToken(Keycloak keycloak) throws VerificationException
    {
        return extractAccessTokenFrom(getAccessTokenString(keycloak));
    }



    private String getAccessTokenString(Keycloak keycloak)
    {
        AccessTokenResponse tokenResponse = getAccessTokenResponse(keycloak);
        return tokenResponse == null ? null : tokenResponse.getToken();
    }



    private ExtendAccessToken extractAccessTokenFrom(String token) throws VerificationException
    {
        if (token == null)
        {
            return null;
        }
        TokenVerifier<AccessToken> tokenVerifier = TokenVerifier.create(token, AccessToken.class);
        ExtendAccessToken accessToken = new ExtendAccessToken();
        accessToken.setToken(tokenVerifier.getToken());
        accessToken.setRawToken(token);
        return accessToken;
    }


    private KeycloakBuilder newKeycloakBuilderWithPasswordCredentials(String username,
            String password)
    {
        return newKeycloakBuilderWithClientCredentials() //
                .username(username) //
                .password(password) //
                .grantType(OAuth2Constants.PASSWORD);
    }



    private KeycloakBuilder newKeycloakBuilderWithClientCredentials()
    {
        KeycloakBuilder builder = KeycloakBuilder.builder() //
                .realm(realmId) //
                .serverUrl(serverUrl)//
                .clientId(clientId) //
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS);
        if (StringUtil.isNotEmpty(clientSecret))
        {
            builder.clientSecret(clientSecret);
        }
        return builder;
    }



    private AccessTokenResponse getAccessTokenResponse(Keycloak keycloak)
    {
        try
        {
            return keycloak.tokenManager().getAccessToken();
        }
        catch (Exception ex)
        {
            return null;
        }
    }



    public String getRealmUrl()
    {
        return serverUrl + "/realms/" + realmId;
    }



    public String getRealmCertsUrl()
    {
        return getRealmUrl() + "/protocol/openid-connect/certs";
    }
}