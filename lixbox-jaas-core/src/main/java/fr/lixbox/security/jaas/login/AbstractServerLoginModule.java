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
package fr.lixbox.security.jaas.login;

import java.lang.reflect.Constructor;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.security.NestableGroup;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

import fr.lixbox.security.jaas.model.enumeration.TypeAuthentification;

/**
 * Cette classe implemente les fonctions de base requises pour faire un
 * login module JAAS.
 * Par ailleurs, elle implemente aussi les besoins pour JBOSS.
 * 
 * Il existe un ensemble d'options:
 * <p>
 * option password-stacking
 * option principalClass
 * option unauthenticatedIdentity
 * option jnpHost   
 * option dsJndiName
 * option userQuery
 * option rolesQuery
 * </p>
 * 
 *  @author ludovic.terral
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractServerLoginModule implements LoginModule
{
    // ----------- Attribut -----------
    private static final Log LOG = LogFactory.getLog(AbstractServerLoginModule.class);
    
    protected Subject subject;
    protected Principal identity;
    protected Object credential;
    
    protected CallbackHandler callbackHandler;
    protected Map sharedState;
    protected Map options;
    protected boolean useFirstPass;    
    protected boolean loginOk;
    protected String principalClassName;
    protected Principal unauthenticatedIdentity;
    protected String jnpHost = "localhost:1099";   
    protected String dsJndiName = "java:/XAOracleDS";
    protected String userQuery = "select NAME from USER where USER_ID=?";
    protected String rolesQuery = "select ROLE_NAME from ROLE where USER_NAME=?";
    protected String jnpUser = "guest";
    protected String jnpPwd = "jboss";
    protected String jnpFactory = "org.jboss.as.naming.InitialContextFactory";
    protected String pathCrl;
    protected String pathKeystore;
    protected String pwdKeystore;
    protected String keyAlias;
        
    
    // ----------- Methode -----------    
    /** 
     * Cette methode initialise le login module. Il enregistre le subject, le callbackHandler
     * et le sharedState pour cette session de login.
     * 
     * @param subject 
     * @param callbackHandler
     * @param sharedState
     * @param options
     */
    public void initialize(final Subject subject, final CallbackHandler callbackHandler,
            final Map sharedState, final Map options)
    {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
        this.principalClassName = (String) options.get("principalClass");
        if (principalClassName == null)
        {
            principalClassName = "fr.lixbox.security.jaas.model.LixboxPrincipal";
        }        
        pathKeystore = (String) options.get("pathKeystore");
        pwdKeystore = (String) options.get("pwdKeystore");
        pathCrl = (String) options.get("pathCrl");
        keyAlias = (String) options.get("keyAlias");
        final String passwordStacking = (String) options.get("password-stacking");
        if( (passwordStacking != null) && passwordStacking.equalsIgnoreCase("useFirstPass") )
        {
            this.useFirstPass = true;
        }
        jnpHost = (String) options.get("jnpHost");
        if (jnpHost == null)
        {
            jnpHost = "localhost:1099";
        }


        final String name = (String) options.get("unauthenticatedIdentity");
        if( name != null )
        {
            try
            {
                this.unauthenticatedIdentity = this.createIdentity(name);
                LOG.trace("Saw unauthenticatedIdentity="+name);
            }
            catch(final Exception e)
            {
                LOG.warn("Failed to create custom unauthenticatedIdentity", e);
            }
        }
        
        
        this.dsJndiName = (String) options.get("dsJndiName");
        this.jnpHost = (String) options.get("jnpHost");

        Object tmp = options.get("principalsQuery");
        if (tmp != null)
        {
            this.userQuery = tmp.toString();
        }
        else if (options.get("userQuery")!=null)
        {
            this.userQuery = options.get("userQuery").toString();
        }
        tmp = options.get("rolesQuery");
        if (tmp != null)
        {
            this.rolesQuery = tmp.toString();
        }
        LOG.trace("CertLoginModule, dsJndiName=" + dsJndiName);
        LOG.trace("jnpHost=" + jnpHost);
        LOG.trace("userQuery=" + userQuery);
        LOG.trace("rolesQuery=" + rolesQuery);
        
        LOG.trace("pathCrl=" + pathCrl);
        LOG.trace("pathKeystore=" + pathKeystore);
        LOG.trace("pwdKeystore=" + pwdKeystore);
        LOG.trace("keyAlias=" + keyAlias);
    }
    
    

    /** 
     * Cette classe assure le login qui consiste a verifier les credentials
     * fournis lors de la demande de login
     */    
    public boolean login() throws LoginException
    {
        loginOk = false;
        if( this.useFirstPass == true )
        {
            try
            {
                final Object identity = this.sharedState.get("javax.security.auth.login.name");
                final Object credential = this.sharedState.get("javax.security.auth.login.password");
                if( (identity != null) && (credential != null) )
                {
                    loginOk = true;
                    return true;
                }
            }
            catch(final Exception e)
            {   
                LOG.error("login failed", e);
            }
        }
        return false;
    }

    
    
    /** 
     * Cette methode commite le login, le principal et les roles dans la session.
     */
    public boolean commit() throws LoginException
    {
        if( loginOk == false )
        {
            return false;
        }

        
        final Set<Principal> principals = this.subject.getPrincipals();
        final Principal identity = this.getIdentity();
        principals.add(identity);
        final Group[] roleSets = this.getRoleSets();
        for (final Group group : roleSets)
        {
            final String name = group.getName();
            Group subjectGroup = this.createGroup(name, principals);
            if( subjectGroup instanceof NestableGroup )
            {
                final SimpleGroup tmp = new SimpleGroup("Roles");
                subjectGroup.addMember(tmp);
                subjectGroup = tmp;
            }
            
            
            final Enumeration<? extends Principal> members = group.members();
            while( members.hasMoreElements() )
            {
                final Principal role = members.nextElement();
                subjectGroup.addMember(role);
            }
        }

        Group callerGroup = null;
        for (Principal principal : principals)
        {
            if (principal instanceof Group)
            {
                Group group = (Group) Group.class.cast(principal);
                if (group.getName().equals("CallerPrincipal"))
                {
                    callerGroup = group;
                    break;
                }
            }
        }
        if (callerGroup == null)
        {
            callerGroup = new SimpleGroup("CallerPrincipal");
            callerGroup.addMember(identity);
            principals.add(callerGroup);
        }
        
        SecurityAssociationActions.setPrincipalInfo(this.identity, this.credential, this.subject);
        return true;
    }

    
    
    /**
     * Cette methode sert a arreter la procedure d'authentification
     */
    public boolean abort() throws LoginException
    {
        LOG.trace("abort");
        return true;
    }
    
    

    /**
     * Cette methode assure la deconnexion.
     */
    public boolean logout() throws LoginException
    {
        LOG.trace("logout");
        final Principal identity = this.getIdentity();
        final Set<Principal> principals = this.subject.getPrincipals();
        principals.remove(identity);
        return true;
    }
    


    protected boolean getUseFirstPass()
    {
        return this.useFirstPass;
    }
    protected Principal getUnauthenticatedIdentity()
    {
        return this.unauthenticatedIdentity;
    }

    
    
    /** 
     * Cette methode edite ou creer un group de principal. En particulier
     * elle est utilisee pour les groupes de roles. 
     * 
     * @return un groupe de principals
     */
    protected Group createGroup(final String name, final Set<Principal> principals)
    {
        Group roles = null;
        final Iterator<Principal> iter = principals.iterator();
        while( iter.hasNext() )
        {
            final Object next = iter.next();
            if( (next instanceof Group) == false )
            {
                continue;
            }
            final Group grp = (Group) next;
            if( grp.getName().equals(name) )
            {
                roles = grp;
                break;
            }
        }
        
        
        if( roles == null )
        {
            roles = new SimpleGroup(name);
            principals.add(roles);
        }
        return roles;
    }
    
        
    
    /** 
     * Cette methode cree un Principal pour le nom d'utilisateur fourni
     *
     * @param username 
     * @return le principal associe
     */
    protected Principal createIdentity(final String username)
        throws Exception
    {
        Principal p = null;
        if( this.principalClassName == null )
        {
            p = new SimplePrincipal(username);
        }
        else
        {
            final ClassLoader loader = Thread.currentThread().getContextClassLoader();
            final Class<?> clazz = loader.loadClass(this.principalClassName);
            final Class<?>[] ctorSig = {String.class,TypeAuthentification.class};
            final Constructor<?> ctor = clazz.getConstructor(ctorSig);
            final Object[] ctorArgs = {username,TypeAuthentification.BASIC};
            p = (Principal) ctor.newInstance(ctorArgs);
        }
        return p;
    }
    
    
    abstract protected Principal getIdentity();
    abstract protected Group[] getRoleSets() throws LoginException;
}
