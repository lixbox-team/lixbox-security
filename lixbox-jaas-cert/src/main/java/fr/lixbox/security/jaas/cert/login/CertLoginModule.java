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
package fr.lixbox.security.jaas.cert.login;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.acl.Group;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.ObjectCallback;

import fr.lixbox.security.cert.parser.CertParser;
import fr.lixbox.security.jaas.login.AbstractServerLoginModule;
import fr.lixbox.security.jaas.model.LixboxPrincipal;
import fr.lixbox.security.jaas.model.enumeration.TypeAuthentification;
import fr.lixbox.security.jaas.model.enumeration.TypeCompte;


/**
 * Ce module realise l'authentification d'un utilisateur au travers
 * de son certificat electronique et d'une base de donnee via un lien JDBC
 * contenant un referentiel utilisateur.
 * 
 * Il existe un ensemble d'options:
 * <p>
 * option password-stacking
 * option principalClass: la classe support du login
 * option unauthenticatedIdentity
 * option jnpHost   
 * option dsJndiName
 * option userQuery
 * option rolesQuery
 * </p>
 * 
 * @author ludovic.terral 
 */
public class CertLoginModule extends AbstractServerLoginModule
{
    // ----------- Attribut -----------
    public static final long serialVersionUID = -365985684758L;
    private static final Log LOG = LogFactory.getLog(CertLoginModule.class);

    private CertParser parser;
    private String certParserClass = "fr.lixbox.security.cert.parser.BasicCertParser";
    
    
    // ----------- Methode -----------    
    public CertLoginModule()
    {
        super();
    }



    /**
     * Cette methode initialise le login module. Il enregistre le subject, le
     * callbackHandler et le sharedState pour cette session de login.
     * 
     * @param subject
     * @param callbackHandler
     * @param sharedState
     * @param options
     */
    @SuppressWarnings("rawtypes")
    @Override
    public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map sharedState, final Map options)
    {
        super.initialize(subject, callbackHandler, sharedState, options);   
        if (options.get("certParserClass")!=null)
        {
            certParserClass = (String) options.get("certParserClass");
        }
        try
        {
            parser = (CertParser) Class.forName(certParserClass).getConstructors()[0].newInstance();
        }
        catch (Exception e)
        {
            LOG.fatal(e);
        }
    }
        
        
    /**
     * Cette methode realise l'authentification de l'utilisateur
     * 
     * @return  true  si utilisateur reconnu et autorise
     *          false si utilisateur non reconnu ou non autorise
     */
    public boolean login() throws LoginException
    {
        try
        {
            this.loginOk = super.login();
        }
        catch (final FailedLoginException fle)
        {
            LOG.trace("CertLoginModule: Impossible d'authentifier l'utilisateur");
        }

        try
        {
            this.getLoginInfo();
            if (parser != null)
            {
                Object certId = this.parser.getCertificateId();
                if (!this.loginOk)
                {
        
                    LOG.trace("Identite presentee:"+certId);
                    if (this.parser.getCertificateId()==null)
                    {
                        certId = this.sharedState.get("javax.security.auth.login.name");
                    }
        
                    if (certId!=null)
                    {
                        if( certId instanceof Principal )
                        {
                            this.identity = (Principal) certId;
                        }
                        else
                        {
                            final String id = certId.toString();
                            try
                            {
                                this.identity = this.createIdentity("",id);
                            }
                            catch(final Exception e)
                            {
                                LOG.trace("Failed to create principal", e);
                                throw new LoginException("Failed to create principal: "+ e.getMessage());
                            }
                        }
                    }
                    else
                    {
                        this.identity = this.unauthenticatedIdentity;
                    }
                    this.loginOk = this.authentifierUserName(this.identity);
                    LOG.info("User '" + this.identity + "' authenticated, loginOk="+this.loginOk);
                }
            }
        }
        catch (Exception e)
        {
            LOG.fatal(e);
        }
        return this.loginOk;
    }



    /**
     * Cette methode verifie l'existence du UserName dans la
     * base de donnees et donc de controler son autorisation a acceder
     * au systeme
     * 
     * @param identity
     * 
     * @return true si authentitfiee
     *         false si refusee
     */
    protected boolean authentifierUserName(final Principal identity)
        throws LoginException
    {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try
        {
            final Properties env = System.getProperties();
            env.put(Context.PROVIDER_URL, this.jnpHost);         
                        
            if (this.jnpHost.contains("4447"))
            {
                env.put(Context.SECURITY_PRINCIPAL, jnpUser);
                env.put(Context.SECURITY_CREDENTIALS, jnpPwd);
                env.put(Context.INITIAL_CONTEXT_FACTORY, jnpFactory); 
            }
            InitialContext ctx = new InitialContext(env);             
            
            final DataSource ds = (DataSource) ctx.lookup(this.dsJndiName);
            conn = ds.getConnection();
            ps = conn.prepareStatement(this.userQuery);
            if ((identity!=null) && (((LixboxPrincipal)identity).getCertificateId()!=null))
            {
                ps.setString(1, ((LixboxPrincipal)identity).getCertificateId());
                rs = ps.executeQuery();
                if (rs.next())
                {
                    ((LixboxPrincipal)identity).setName(rs.getString(1));
                    ((LixboxPrincipal)identity).setTypeCompte(TypeCompte.COMPTE_UTILISATEUR);
                    LOG.trace("Utilisateur autorise");
                    this.closeConnection(conn,ps,rs);
                    return true;
                }
                else
                {
                    LOG.trace("Utilisateur non autorise");
                    this.closeConnection(conn,ps,rs);
                    return false;
                }
            }
        }
        catch (final Exception e)
        {
            LOG.error(e);
        }
        this.closeConnection(conn,ps,rs);
        throw new FailedLoginException("Utilisateur non reconnu");
    }



    /**
     * Execute the rolesQuery against the dsJndiName to obtain the roles for
     * the authenticated user.
     * 
     * @return Group[] containing the sets of roles
     */
    protected Group[] getRoleSets() throws LoginException
    {
        LOG.trace("INVOCATION CertLoginModule.getRoleSets()");
        LOG.trace("for user " + this.identity);

        final List<String> roles = new ArrayList<String>();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try
        {
            final Properties env = System.getProperties();
            env.put(Context.PROVIDER_URL, this.jnpHost);
            
            
            InitialContext ctx = null;
            if (this.jnpHost.contains("localhost"))
            {
                ctx = new InitialContext();
            }
            else
            {
                ctx = new InitialContext(env);
            }
            
            
            final DataSource ds = (DataSource) ctx.lookup(this.dsJndiName);
            conn = ds.getConnection();
            ps = conn.prepareStatement(this.rolesQuery);
            ps.setString(1, ((LixboxPrincipal)this.identity).getCertificateId());
            rs = ps.executeQuery();
            while (rs.next())
            {
                final String roleName = rs.getString(1);
                roles.add(roleName);
            }
        }
        catch (final NamingException e)
        {
            LOG.error(e);
        }
        catch (final SQLException e)
        {
            LOG.error(e);
        }
        this.closeConnection(conn,ps,rs);

        final Group[] groups = { new SimpleGroup("Roles"), new SimpleGroup("CallerPrincipal") };
        for (final String string : roles)
        {
            final String roleName = string;
            final SimplePrincipal role = new SimplePrincipal(roleName);
            LOG.debug("role " + roleName);
            groups[0].addMember(role);
        }
        LOG.trace(groups[0]);   
        
        groups[1].addMember(identity);
        return groups;
    }



    protected Principal getIdentity()
    {
        return this.identity;
    }



    private void closeConnection(final Connection conn, final PreparedStatement ps, final ResultSet rs)
    {
        try
        {
            if (rs!=null)
            {
                rs.close();
            }
        }
        catch (final SQLException e1)
        {
            LOG.error(e1);
        }
        try
        {
            if (ps!=null)
            {
                ps.close();
            }
        }
        catch (final SQLException e1)
        {
            LOG.error(e1);
        }
        try
        {
            if (conn!=null)
            {
                conn.close();
            }
        }
        catch (final SQLException e1)
        {
            LOG.error(e1);
        }
    }



    /**
     * Cette methode popule un principal qui contient l'user_id et le name
     * 
     * @param name
     * @param userId
     * 
     * @return un PamCertificatPrincipal popule
     */
    protected Principal createIdentity(final String name, final String userId)
        throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException,
        IllegalArgumentException, InstantiationException, InvocationTargetException
    {
        Principal p = null;
        if( this.principalClassName == null )
        {
            p = new SimplePrincipal(name);
        }
        else
        {
            final ClassLoader loader = Thread.currentThread().getContextClassLoader();
            final Class<?> clazz = loader.loadClass(this.principalClassName);
            final Class<?>[] ctorSig = {String.class,String.class,TypeAuthentification.class};
            final Constructor<?> ctor = clazz.getConstructor(ctorSig);
            final Object[] ctorArgs = {name,userId, TypeAuthentification.CERTIFICAT};
            p = (Principal) ctor.newInstance(ctorArgs);
        }
        return p;
    }



    /**
     * Cette methode recupere et affiche les informations concernant le certificat utilise pour le login
     * @throws FailedLoginException 
     */
    @SuppressWarnings("unchecked")
    private void getLoginInfo() throws FailedLoginException
    {
        if (this.callbackHandler == null)
        {
            LOG.debug("ERROR : CALLBACKHANDLER NULL");
        }
        else
        {
            final NameCallback nc = new NameCallback("username");
            final ObjectCallback oc = new ObjectCallback("certs");
            final Callback[] callbacks = { nc, oc };
            try
            {
                this.callbackHandler.handle(callbacks);
                credential = oc.getCredential();
                
                if (credential instanceof String)
                {
                    throw new UnsupportedCallbackException(oc);
                }
                else
                {
                    if (credential.getClass().isArray())
                    {
                        if (credential.getClass().getComponentType().equals(X509Certificate.class))
                        {
                            final X509Certificate[] certs = (X509Certificate[]) credential;
                            verifierChaineCertifServClient(certs);
                            sharedState.put(parser.getCertificateDatas().get("serialNumber"), certs[0]);
                        }
                        else
                        {
                            throw new UnsupportedCallbackException(oc);
                        }
                    }
                    else
                    {
                        X509Certificate cert = (X509Certificate) credential;                        
                        sharedState.put(parser.getCertificateDatas().get("serialNumber"), cert);
                    }
                }
            }
            catch (final IOException e)
            {
                LOG.error(e);
            }
            catch (final UnsupportedCallbackException e)
            {
                LOG.trace(e);
            }
        }
    }



    private void verifierChaineCertifServClient(X509Certificate[] certs)
        throws FailedLoginException
    {
        try
        {
            // ouvre le fichier de keystore et va le charger  dans le keystore (ks)
            FileInputStream fis = new FileInputStream(pathKeystore);
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(fis, pwdKeystore.toCharArray());
    
            if (fis != null) //ferme fichier
            {
                fis.close();
                fis = null;
            }
    
            
            // ouvre le cretificat avec l'alias
            Certificate[] chaine = ks.getCertificateChain(keyAlias);
            X509Certificate subCa = (X509Certificate) chaine[1];
            if (!certs[1].getPublicKey().equals(subCa.getPublicKey())
                    ||!certs[1].getIssuerDN().equals(subCa.getIssuerDN()))                
            {                
                throw new FailedLoginException("Chaine cliente differente de la chaine serveur");
            }
        }
        catch (Exception e)        
        {
            LOG.fatal(e);
            throw new FailedLoginException();
        }
    }
}