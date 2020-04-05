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

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

/**
 * Cette suite de tests sert à vérifier le bon fonctionnement de la 
 * classe PBEWithMD5AndDESUtil
 *  
 * @author ludovic.terral
 */
public class PBEWithMD5AndDESUtilTest
{
    @Test
    public final void testEncryptString()
    {
        byte[] result = new byte[] {96, 116, -75, 26, 38, -105, 101, -27};
        byte[] tmp = PBEWithMD5AndDESUtil.encrypt("hello");
        Assert.assertTrue("mauvaise convertion", Arrays.equals(result, tmp));
    }

    
    
    @Test
    public final void testDecryptToString()
    {
        byte[] result = new byte[] {96, 116, -75, 26, 38, -105, 101, -27};
        Assert.assertEquals("mauvaise convertion", "hello", PBEWithMD5AndDESUtil.decrypt(result));
    }
}
