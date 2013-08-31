package sibbo.bitmessage.crypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.junit.Test;

import sibbo.bitmessage.network.protocol.EncryptedMessage;
import sibbo.bitmessage.network.protocol.V1MessageFactory;

public class CryptManagerTest {
	@Test
	public void testECIES() throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException {
		CryptManager.getInstance();
		String message = "dfschamlxeadgsfredcaxds";
		KeyPair key = CryptManager.getInstance().generateEncryptionKeyPair();
		byte[] source = message.getBytes("UTF-8");

		EncryptedMessage encrypted = CryptManager.getInstance().encrypt(source, (JCEECPublicKey) key.getPublic(),
				new V1MessageFactory());

		for (int i = 0; i < encrypted.getEncrypted().length; i++) {
			if (i % 8 == 0)
				System.out.println();

			String s = Integer.toHexString(encrypted.getEncrypted()[i] & 0xFF) + " ";
			if (s.length() == 2) {
				s = "0" + s;
			}

			System.out.print(s);
		}

		System.out.println();

		byte[] decrypted = CryptManager.getInstance().decrypt(encrypted, (JCEECPrivateKey) key.getPrivate());

		String result = new String(decrypted, "UTF-8");

		assertEquals(message + " != " + result, message, result);
	}

	@Test
	public void testSigning() {
		Random r = new Random();
		byte[] data = new byte[1021];
		r.nextBytes(data);
		KeyPair key = CryptManager.getInstance().generateSigningKeyPair();

		byte[] signature = CryptManager.getInstance().sign(data, (JCEECPrivateKey) key.getPrivate());

		assertTrue(CryptManager.getInstance().verifySignature(data, signature, (JCEECPublicKey) key.getPublic()));
	}
}