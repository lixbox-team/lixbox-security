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
