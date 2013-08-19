package sibbo.bitmessage.crypt;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.junit.Test;

public class CryptManagerTest {
	@Test
	public void testECIES() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		CryptManager.getInstance();
		String message = "dfschamlxeadgsfredcaxds";
		KeyDataPair source = new KeyDataPair(CryptManager.getInstance().generateKeyPair(), message.getBytes("UTF-8"));

		KeyDataPair encrypted = CryptManager.getInstance().encrypt(source);

		for (int i = 0; i < encrypted.getData().length; i++) {
			if (i % 8 == 0)
				System.out.println();

			String s = Integer.toHexString(encrypted.getData()[i] & 0xFF) + " ";
			if (s.length() == 2) {
				s = "0" + s;
			}

			System.out.print(s);
		}

		System.out.println();

		KeyDataPair decrypted = CryptManager.getInstance().tryDecryption(encrypted);

		String result = new String(decrypted.getData(), "UTF-8");

		assertEquals(message + " != " + result, message, result);
	}
}