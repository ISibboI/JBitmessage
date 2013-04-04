package sibbo.bitmessage;

import java.util.logging.Logger;

public class Options {
	private static final Logger LOG = Logger.getLogger(Options.class.getName());

	private static final Options instance = new Options();

	public static Options getInstance() {
		return instance;
	}

	public int getMaxMessageLength() {
		return 10 * 1024 * 1024;
	}

	public long getMaxInvLength() {
		return 50_000;
	}

	public int getPOWAverageNonceTrialsPerByte() {
		return 320;
	}

	public int getPOWPayloadLengthExtraBytes() {
		return 14_000;
	}

	public float getPOWSystemLoad() {
		return 0.5f;
	}
}