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
