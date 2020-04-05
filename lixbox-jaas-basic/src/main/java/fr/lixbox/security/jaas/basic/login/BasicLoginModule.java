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
package fr.lixbox.security.jaas.basic.login;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.acl.Group;
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
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

import fr.lixbox.security.crypto.util.PBEWithMD5AndDESUtil;
import fr.lixbox.security.jaas.login.AbstractServerLoginModule;
import fr.lixbox.security.jaas.model.LixboxPrincipal;


/**
 * Ce module realise l'authentification d'un utilisateur au travers
 * de son user_name, de son password et d'une base de donnees via un lien JDBC 
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
 * option passwordEncoding
 * 
 * @author ludovic.terral 
 */
@SuppressWarnings({"rawtypes","unchecked"})
public class BasicLoginModule extends AbstractServerLoginModule
{
    // ----------- Attribut -----------
    public static final long serialVersionUID = -365985684758L;
    private static final Log LOG = LogFactory.getLog(BasicLoginModule.class);
    
    protected byte[] encodedCredential;
    protected String passwordEncoding = "";
    protected String typeEncode = "";
    
    
    
    // ----------- Methode -----------
    public BasicLoginModule()
    {
        super();
    }

        
    
    /**
     * Initialize this LoginModule.
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
         Map sharedState, Map options)
    {        
        super.initialize(subject, callbackHandler, sharedState, options);
        
        passwordEncoding = (String) options.get("passwordEncoding");
        if (passwordEncoding == null)
        {
            passwordEncoding = "";
        }        
        
        typeEncode = (String) options.get("typeEncode");
        if (typeEncode == null)
        {
            typeEncode = "String";
        }         
        LOG.trace("UserPasswordLoginModule, dsJndiName=" + dsJndiName);
        LOG.trace("jnpHost=" + jnpHost);
        LOG.trace("passwordEncoding=" + passwordEncoding);
        LOG.trace("userQuery=" + userQuery);
        LOG.trace("rolesQuery=" + rolesQuery);
    }
    
    
    
    /**
     * Cette methode realise l'authentification de l'utilisateur
     * 
     * @return  true  si utilisateur reconnu et autorise
     *          false si utilisateur non reconnu ou non autorise
     */
    @Override
    public boolean login() throws LoginException
    {
        try
        {
            loginOk = super.login();
        }
        catch (FailedLoginException fle)
        {
            LOG.trace("UserPasswordLoginModule: Impossible d'authentifier l'utilisateur",fle);
        }
        
        if (loginOk)            
        {
            return loginOk;
        }
        
        Object username;
        if (callbackHandler == null)
        {
            throw new LoginException("Erreur: Le CallbackHandler n'est pas disponnible pour populer les informations d'authentification");
        }
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("[" + getClass().getName()+ "] username: ");
        callbacks[1] = new PasswordCallback("[" + getClass().getName()+ "] motdepasse: ", true);
        try
        {
            callbackHandler.handle(callbacks);
            username = ((NameCallback) callbacks[0]).getName();                  
            
            if (((PasswordCallback) callbacks[1]) != null && ((PasswordCallback) callbacks[1]).getPassword() instanceof char[])
            {
                credential = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());    
            }
            if (!"".equalsIgnoreCase(passwordEncoding) && credential!=null)
            {
                try
                {
                    encodedCredential = getEncodedPassword((String) credential);
                }
                catch (NoSuchAlgorithmException e)
                {
                    LOG.error(e);
                    throw new UnsupportedCallbackException(callbacks[1]);
                }
            }
            
        }
        catch (java.io.IOException ioe)
        {
            LOG.trace(ioe);
            throw new LoginException(ioe.toString());
        }
        catch (UnsupportedCallbackException uce)
        {
            LOG.trace(uce);
            throw new LoginException(
                    "Error: "
                            + uce.getCallback().toString()
                            + " not available to garner authentication information from the user");
        }

        LOG.trace("Identite presentee:"+username);        
        if (username==null)
        {
            username = sharedState.get("javax.security.auth.login.name");                
        }
            
        if (username!=null)
        {
            if( username instanceof Principal )
            {
                identity = (Principal) username;
            }
            else
            {
                String name = username.toString();
                try
                {
                    identity = createIdentity(name);
                }
                catch(Exception e)
                {
                    LOG.trace("Failed to create principal", e);
                    throw new LoginException("Failed to create principal: "+ e.getMessage());
                }
            }
        }
        else            
        {
            identity = unauthenticatedIdentity;
        }
        loginOk = authentifierUserName(identity, encodedCredential);
        LOG.debug("User '" + identity + "' authenticated, loginOk="+loginOk);
        return loginOk;
    }
    
    

    /** 
     * Cette methode verifie l'existence du UserName dans la 
     * base de donnees et donc de controler son autorisation a acceder 
     * au systeme
     * 
     * @param userName 
     * @return true si authentitfiee
     *         false si refusee
     */
    protected boolean authentifierUserName(Principal userName, Object credential) 
        throws LoginException
    {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try 
        {                       
            Properties env = System.getProperties();
            env.put(Context.PROVIDER_URL, jnpHost);
            InitialContext ctx;
            if (jnpHost.contains("localhost"))
            {
                ctx = new InitialContext();
            }
            else
            {
                ctx = new InitialContext(env);
            }             
            DataSource ds = (DataSource) ctx.lookup(dsJndiName);
            conn = ds.getConnection();
            ps = conn.prepareStatement(userQuery);
           
            if (userName!=null && userName.getName()!=null&&(credential != null && !credential.toString().contains("ObjectId")))
            {
                ps.setString(1, userName.getName());
                Object usedCredential = encodedCredential!=null&&encodedCredential.length>0?encodedCredential:credential;
                if ("String".equals(typeEncode))
                {
                    if (usedCredential instanceof String)
                    {
                        ps.setObject(2, usedCredential);
                    }
                    else
                    {
                        ps.setObject(2, new String((byte[])usedCredential, StandardCharsets.UTF_8));
                    }
                }
                else
                {
                    ps.setObject(2, usedCredential);
                }
                rs = ps.executeQuery();
                if (rs.next())
                {
                    try 
                    {
                        ((LixboxPrincipal)userName).setCertificateId((String)rs.getObject(2)); 
                    } 
                    catch (Exception e) 
                    {
                        LOG.trace(e);
                        LOG.trace("Pas de UserId en base");    
                    }
                    
                    identity=(LixboxPrincipal)userName;                 
                    LOG.trace("Utilisateur autorise");                  
                    sharedState.put("javax.security.auth.login.name",identity);  
                    closeConnection(conn,ps,rs);
                    return true;                    
                }
                else
                {
                    LOG.trace("Utilisateur non autorise");   
                    closeConnection(conn,ps,rs);
                    return false;
                }
                
            }
        } 
        catch (NamingException|SQLException e) 
        {
            LOG.error(e);
        } 
        closeConnection(conn,ps,rs);
        throw new FailedLoginException("Utilisateur non reconnu");
    }
    
    

    /** 
     * Execute the rolesQuery against the dsJndiName to obtain the roles for 
     * the authenticated user.
     * 
     * @return Group[] containing the sets of roles
     */
    @Override
    protected Group[] getRoleSets() throws LoginException
    {
        LOG.trace("INVOCATION BusinessLoginModule.getRoleSets()");
        LOG.trace("for user " + identity);

        List<String> roles = new ArrayList<String>();
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try 
        {                       
            Properties env = System.getProperties();
            env.put(Context.PROVIDER_URL, jnpHost);
            InitialContext ctx;
            if (jnpHost.contains("localhost"))
            {
                ctx = new InitialContext();
            }
            else
            {
                ctx = new InitialContext(env);
            }     
            DataSource ds = (DataSource) ctx.lookup(dsJndiName);
            conn = ds.getConnection();
            ps = conn.prepareStatement(rolesQuery);
            ps.setString(1, identity.getName());
            rs = ps.executeQuery();
            while (rs.next())
            {
                String roleName = rs.getString(1);
                roles.add(roleName);
            }
        }
        catch (NamingException e) 
        {
            LOG.error(e);
        } 
        catch (SQLException e) 
        {
            LOG.error(e);
        }
        closeConnection(conn,ps,rs);

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
    
    
    
    protected static void closeConnection(Connection conn, PreparedStatement ps, ResultSet rs)
    {
        try 
        {
            if (rs!=null)
            {
                rs.close();
            }
        } 
        catch (SQLException e1) 
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
        catch (SQLException e1) 
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
        catch (SQLException e1) 
        {
            LOG.error(e1);
        }
    }
    
    

    public byte[] getEncodedPassword(String password)
        throws NoSuchAlgorithmException
    {
        byte[] encodedPassword=new byte[0];
        try
        {            
            if ("MD5".equalsIgnoreCase(passwordEncoding))
            {
                byte[] uniqueKey = password.getBytes(StandardCharsets.UTF_8);
                byte[] hash;
                hash = MessageDigest.getInstance(passwordEncoding).digest(uniqueKey);
                StringBuilder hashString = new StringBuilder();
                for (int i = 0; i < hash.length; ++i)
                {
                    String hex = Integer.toHexString(hash[i]);
                    if (hex.length() == 1)
                    {
                        hashString.append('0');
                        hashString.append(hex.charAt(hex.length() - 1));
                    }
                    else
                    {
                        hashString.append(hex.substring(hex.length() - 2));
                    }
                }
                encodedPassword = hashString.toString().getBytes(StandardCharsets.UTF_8);
            }
            if ("PBEWithMD5".equalsIgnoreCase(passwordEncoding))
            {
                encodedPassword = PBEWithMD5AndDESUtil.encrypt(password);
            }
        }
        catch (Exception e)
        {
            LOG.error(e);
        }
        return encodedPassword;
    }
    


    @Override
    protected Principal getIdentity() 
    { 
        return identity; 
    }
}