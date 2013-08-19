package sibbo.bitmessage.network.protocol;

import static org.junit.Assert.assertEquals;

import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.junit.Test;

import sibbo.bitmessage.crypt.CryptManager;

public class UtilTest {
	@Test
	public void testKeyEncoding() {
		JCEECPublicKey key = (JCEECPublicKey) CryptManager.getInstance().generateKeyPair().getPublic();

		assertEquals("The keys don't match.", key, Util.getPublicKey(Util.getBytes(key)));
	}
}
