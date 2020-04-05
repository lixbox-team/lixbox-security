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
package fr.lixbox.security.jaas.login;

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;

import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SecurityContextFactory;

/** A PrivilegedAction implementation for setting the SecurityAssociation
 * principal and credential
 */
public class SecurityAssociationActions
{
   private static class SetPrincipalInfoAction implements PrivilegedAction<Object>
   {
      Principal principal;
      Object credential;
      Subject subject;
      SetPrincipalInfoAction(Principal principal, Object credential, Subject subject)
      {
         this.principal = principal;
         this.credential = credential;
         this.subject = subject;
      }
      
      public Object run()
      {
         //Always create a new security context
         SecurityContext sc = null;
         try
         {
            sc = SecurityContextFactory.createSecurityContext(principal, 
                                                credential, subject, "CLIENT_LOGIN_MODULE");
         }
         catch (Exception e)
         {
            throw new RuntimeException(e);
         }          
         setSecurityContext(sc); 
         
         credential = null;
         principal = null;
         subject = null;
         return null;
      }
   }
   private static class PopPrincipalInfoAction implements PrivilegedAction<Object>
   {
      public Object run()
      {
         if(!getServer())
           popSecurityContext();
         return null;
      }
   }
   private static class ClearAction implements PrivilegedAction<Object>
   {
      static PrivilegedAction<Object> ACTION = new ClearAction();
      public Object run()
      {
         if(!getServer())
           SecurityContextAssociation.clearSecurityContext(); 
         return null;
      }
   }
   private static class GetSubjectAction implements PrivilegedAction<Subject>
   {
      static PrivilegedAction<Subject> ACTION = new GetSubjectAction();
      public Subject run()
      {
         Subject subject = SecurityContextAssociation.getSubject();
         return subject;
      }
   }
   private static class GetPrincipalAction implements PrivilegedAction<Principal>
   {
      static PrivilegedAction<Principal> ACTION = new GetPrincipalAction();
      public Principal run()
      {
         Principal principal = SecurityContextAssociation.getPrincipal();
         return principal;
      }
   }
   private static class GetCredentialAction implements PrivilegedAction<Object>
   {
      static PrivilegedAction<Object> ACTION = new GetCredentialAction();
      public Object run()
      {
         Object credential = SecurityContextAssociation.getCredential();
         return credential;
      }
   }
   
   static void clearSecurityContext(final SecurityContext sc)
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      { 
         public Object run()
         {
            SecurityContextAssociation.clearSecurityContext();
            return null;
         }
      });
   }
   
   static void setSecurityContext(final SecurityContext sc)
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      { 
         public Object run()
         {
            SecurityContextAssociation.setSecurityContext(sc); 
            return null;
         }
      });
   }
   
   static SecurityContext getSecurityContext()
   {
      return AccessController.doPrivileged(new PrivilegedAction<SecurityContext>()
      { 
         public SecurityContext run()
         {
            return SecurityContextAssociation.getSecurityContext(); 
         }
      });
   }
   
   static void pushSecurityContext(final Principal p, final Object cred, 
         final Subject subject, final String securityDomain)
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      { 
         public Object run()
         {
            SecurityContext sc;
            try
            {
               sc = SecurityContextFactory.createSecurityContext(p, cred, 
                     subject, securityDomain);
            }
            catch (Exception e)
            {
               throw new RuntimeException(e);
            }
            setSecurityContext(sc);
            return null;
         }
      });
   }
   
   static void popSecurityContext()
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      { 
         public Object run()
         {
            SecurityContext sc = getSecurityContext();
            if (sc != null)
            {
               sc.getUtil().createSubjectInfo(null, null, null);
            }
            return null;
         }
      });
   }

   static void setPrincipalInfo(Principal principal, Object credential, Subject subject)
   {
      SetPrincipalInfoAction action = new SetPrincipalInfoAction(principal, credential, subject);
      AccessController.doPrivileged(action);
   }
   static void popPrincipalInfo()
   {
      PopPrincipalInfoAction action = new PopPrincipalInfoAction();
      AccessController.doPrivileged(action);
   }

   static Boolean getServer()
   {
      return AccessController.doPrivileged(new PrivilegedAction<Boolean>()
      {
         public Boolean run()
         {
            return !SecurityContextAssociation.isClient();
         }
      });
   }
   
   static void setClient()
   {
      AccessController.doPrivileged(new PrivilegedAction<Object>()
      {
         public Object run()
         {
            SecurityContextAssociation.setClient();
            return null;
         }
      });
   }
   
   static void clear()
   {
      AccessController.doPrivileged(ClearAction.ACTION);
   }
   static Subject getSubject()
   {
      Subject subject = (Subject) AccessController.doPrivileged(GetSubjectAction.ACTION);
      return subject;
   }
   static Principal getPrincipal()
   {
      Principal principal = (Principal) AccessController.doPrivileged(GetPrincipalAction.ACTION);
      return principal;
   }
   static Object getCredential()
   {
      Object credential = AccessController.doPrivileged(GetCredentialAction.ACTION);
      return credential;
   }
   
   static SecurityContext createSecurityContext(final String securityDomain) 
   throws PrivilegedActionException
   {
      return AccessController.doPrivileged(new PrivilegedExceptionAction<SecurityContext>()
      {
         public SecurityContext run() throws Exception
         {
            return SecurityContextFactory.createSecurityContext(securityDomain);
         }
      });
   }
}