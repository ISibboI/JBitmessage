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
}