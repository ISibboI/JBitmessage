package sibbo.bitmessage;

import java.io.IOException;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * A class with a method to initialize the logging system.
 * 
 * @author Sebastian Schmidt
 * @version 1.0
 */
public final class LoggingInitializer {
	private static final Logger LOG = Logger.getLogger(LoggingInitializer.class
			.getName());

	/** Utility class. */
	private LoggingInitializer() {
	}

	public static void initializeLogging() {
		System.setProperty("java.util.logging.config.file",
				"logging.properties");

		try {
			LogManager.getLogManager().readConfiguration();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
}