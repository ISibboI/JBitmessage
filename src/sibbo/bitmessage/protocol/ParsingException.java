package sibbo.bitmessage.protocol;

import java.util.logging.Logger;

public class ParsingException extends Exception {
	private static final Logger LOG = Logger.getLogger(ParsingException.class
			.getName());

	public ParsingException(String message) {
		super(message);
	}
}
