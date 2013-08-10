package sibbo.bitmessage.crypt;


import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.junit.Test;

public class CryptManagerTest {
	@Test
	public void testECIES() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		CryptManager.getInstance();
		String message = "dfschamlxeadgsfredcaxds";
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES", "BC");
		kpg.initialize(32 * 8);
		KeyDataPair source = new KeyDataPair(kpg.generateKeyPair(), message.getBytes("UTF-8"));
		
		KeyDataPair encrypted = CryptManager.getInstance().encrypt(source);
		KeyDataPair decrypted = CryptManager.getInstance().tryDecryption(encrypted);
		
		String result = new String(decrypted.getData(), "UTF-8");
		
		assertEquals(message + " != " + result,message, result);
	}
}