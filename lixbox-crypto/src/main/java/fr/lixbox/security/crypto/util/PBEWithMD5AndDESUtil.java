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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import fr.lixbox.common.util.StringUtil;

/**
 * Cette classe assure l'encodage et le decodage en utilisant le PBEWithMD5
 * 
 * @author ludovic.terral
 * 
 */
public class PBEWithMD5AndDESUtil
{
    // ----------- Attribut -----------   
    private static final String SALT = "DgLtMRbV";
    private static final String serialVersionUID = "4044757122869505855";



    // ----------- Methode -----------   
    public static byte[] encrypt(String data)
    {
        byte[] encodedData = null;
        if (StringUtil.isEmpty(data))
        {
            return encodedData;
        }        
        try
        {       
            encodedData = encrypt(data.getBytes(StandardCharsets.UTF_8), SALT);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return encodedData; 
    }
    
    
    
    public static byte[] encrypt(String data, String salt)
    {
        byte[] encodedData = null;
        if (StringUtil.isEmpty(data))
        {
            return encodedData;
        }        
        try
        {       
            encodedData = encrypt(data.getBytes(StandardCharsets.UTF_8), salt);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return encodedData; 
    }

    
    
    public static byte[] encrypt(byte[] datas, String salt)
    {
        byte[] encodedData = null;
        if (datas==null||datas.length==0)
        {
            return encodedData;
        }        
        try
        {
            PBEParameterSpec paramSpec = new PBEParameterSpec(salt.getBytes(StandardCharsets.UTF_8), 20);
            PBEKeySpec keySpec = new PBEKeySpec((serialVersionUID+"").toCharArray());
            SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secret = kf.generateSecret(keySpec);
            Cipher c = Cipher.getInstance("PBEWithMD5AndDES");
            c.init(Cipher.ENCRYPT_MODE, secret, paramSpec);
            encodedData = c.doFinal(datas);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return encodedData; 
    }
    
    

    public static byte[] decrypt(byte[] data, String salt)
    {        
        byte[] decoded = new byte[0];
        if (data==null)
        {
            return decoded;
        }
        try
        {
            PBEParameterSpec paramSpec = new PBEParameterSpec(salt.getBytes(StandardCharsets.UTF_8), 20);
            PBEKeySpec keySpec = new PBEKeySpec((serialVersionUID+"").toCharArray());
            SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey secret = kf.generateSecret(keySpec);
            Cipher c = Cipher.getInstance("PBEWithMD5AndDES");
            c.init(Cipher.DECRYPT_MODE, secret, paramSpec);
            decoded = c.doFinal(data);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return decoded;         
    }
    
    

    public static String decryptToString(byte[] data, String salt)
    {        
        String decoded = "";
        if (data==null)
        {
            return decoded;
        }
        try
        {
            decoded = new String(decrypt(data, salt), StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return decoded;         
    }

    

    public static String decrypt(byte[] data)
    {        
        String decoded = "";
        if (data==null)
        {
            return decoded;
        }
        try
        {
            decoded = new String(decrypt(data, SALT), StandardCharsets.UTF_8);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return decoded;         
    }
}   