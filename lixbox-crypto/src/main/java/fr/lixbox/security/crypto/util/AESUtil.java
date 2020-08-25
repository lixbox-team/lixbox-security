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