package sibbo.bitmessage.network.protocol;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.junit.Test;

import sibbo.bitmessage.crypt.CryptManager;

public class EncryptedMessageTest {
	@Test
	public void testParsingAndCreation() throws IOException, ParsingException {
		Random r = new Random();

		byte[] iv = new byte[16];
		byte[] encrypted = new byte[16 * 16];
		byte[] mac = new byte[32];

		r.nextBytes(iv);
		r.nextBytes(encrypted);
		r.nextBytes(mac);

		JCEECPublicKey key = (JCEECPublicKey) CryptManager.getInstance().generateKeyPair().getPublic();

		EncryptedMessage source = new EncryptedMessage(iv, key, encrypted, mac);
		byte[] encoded = source.getBytes();
		EncryptedMessage generated = new EncryptedMessage(new InputBuffer(new ByteArrayInputStream(encoded), 128,
				encoded.length));

		assertTrue("The IVs don't match.", Arrays.equals(generated.getIV(), iv));
		assertEquals("The keys don't match.", key, generated.getPublicKey());
		assertTrue("The encrypted data doesn't match.", Arrays.equals(generated.getEncrypted(), encrypted));
		assertTrue("The macs don't match.", Arrays.equals(generated.getMac(), mac));
	}
}
