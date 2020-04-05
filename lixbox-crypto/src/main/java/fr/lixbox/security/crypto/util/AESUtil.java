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
package fr.lixbox.security.crypto.util;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Cette classe assure l'encodage et le decodage en utilisant AES
 * 
 * @author ludovic.terral
 */
public class AESUtil
{
    // ----------- Attribut -----------   
    private static final Log LOG = LogFactory.getLog(AESUtil.class);
    private static final String SALT = "MB0rmXYPuG7Y4nWC";



    // ----------- Methode -----------   
    public static byte[] encrypt(String texte, String secret)
    {
        byte[] byteData = null;
        try
        {
            byte[] iv = SALT.getBytes(StandardCharsets.UTF_8);
            GCMParameterSpec spec = new GCMParameterSpec(16*8, iv);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] encKey = secret.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec key = new SecretKeySpec(encKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key,spec);
            byteData = cipher.doFinal(texte.getBytes(StandardCharsets.UTF_8));
        }
        catch (Exception e)
        {
            LOG.error(e);
            return null;
        }
        return byteData;
    }



    public static String decrypt(byte[] cipherText, String secret)
    {
        String texte = null;
        try
        {
            byte[] iv = SALT.getBytes(StandardCharsets.UTF_8);
            GCMParameterSpec spec = new GCMParameterSpec(16*8, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] encKey = secret.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec key = new SecretKeySpec(encKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            texte = new String(cipher.doFinal(cipherText),StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            LOG.error(e);
            return null;
        }
        return texte;
    }
}