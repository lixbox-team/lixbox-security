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
 * classe AESUtil
 *  
 * @author ludovic.terral
 */
public class AESUtilTest
{
    private static final String SECRET="MySecretKey123!=";
    private static final String MY_STRING="La phrase a été encrypté et décrypté correctement.";
    private static final byte[] ENCODED=new byte[] {-121, -109, 42, -91, 6, 51, 36, -76, 8, -13, 22, 106, -60, 98, -44, -67, 27, -56, 109, 109, 25, -124, -122, 83, -106, 82, -103, 18, -119, 84, 79, 55, 56, -15, 24, 64, -60, 10, 109, -17, -51, -126, -29, 91, -63, 58, -3, -118, -36, 126, 13, 16, -122, 66, -55, 17, -123, -76, -94, 77, -72, -10, -36, -94, 32, -109, -99, 48, -53, -43, -3};
    
    
    @Test
    public final void testEncrypt()
    {
        byte[] result = AESUtil.encrypt(MY_STRING, SECRET);
        Assert.assertTrue("mauvaise convertion", Arrays.equals(result, ENCODED));
    }



    @Test
    public final void testDecrypt()
    {
        Assert.assertEquals("mauvaise convertion", MY_STRING, AESUtil.decrypt(ENCODED, SECRET));
    }
}
