package sibbo.bitmessage;

import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Options extends Properties {
	private static final Logger LOG = Logger.getLogger(Options.class.getName());

	private static final Options defaults = new Options(null);

	static {
		defaults.setProperty("global.version", "0.0.0");
		defaults.setProperty("global.name", "JBitmessage");

		defaults.setProperty("protocol.maxMessageLength", 10 * 1024 * 1024);
		defaults.setProperty("protocol.maxInvLength", 50_000);
		defaults.setProperty("protocol.services", 1);
		defaults.setProperty("protocol.remoteServices", 1);
		defaults.setProperty("pow.averageNonceTrialsPerByte", 320);
		defaults.setProperty("pow.payloadLengthExtraBytes", 14_000);
		defaults.setProperty("pow.systemLoad", 0.5f);
		defaults.setProperty("network.connectTimeout", 5_000);
		defaults.setProperty("network.timeout", 10_000);
		defaults.setProperty("network.listenPort", 8443);
		defaults.setProperty(
				"network.userAgent",
				"/" + defaults.getString("global.name") + ":"
						+ defaults.getString("global.version") + "/");
	}

	private static final Options instance = new Options(defaults);

	public static Options getInstance() {
		return instance;
	}

	private Options(Properties defaults) {
		super(defaults);
	}

	public Object setProperty(String key, float value) {
		return setProperty(key, String.valueOf(value));
	}

	public Object setProperty(String key, int value) {
		return setProperty(key, String.valueOf(value));
	}

	public Object setProperty(String key, long value) {
		return setProperty(key, String.valueOf(value));
	}

	public int getInt(String key) {
		try {
			return Integer.valueOf(getProperty(key));
		} catch (NumberFormatException e) {
			LOG.log(Level.SEVERE, "Not an integer: " + getProperty(key), e);
			System.exit(1);
			return 0;
		}
	}

	public float getFloat(String key) {
		try {
			return Float.valueOf(getProperty(key));
		} catch (NumberFormatException e) {
			LOG.log(Level.SEVERE, "Not a float: " + getProperty(key), e);
			System.exit(1);
			return 0;
		}
	}

	public String getString(String key) {
		return getProperty(key);
	}

	@Override
	public String getProperty(String key) {
		String result = super.getProperty(key);

		if (result == null) {
			throw new NullPointerException("Property not found: " + key);
		} else {
			return result;
		}
	}

	public long getLong(String key) {
		try {
			return Long.valueOf(getProperty(key));
		} catch (NumberFormatException e) {
			LOG.log(Level.SEVERE, "Not a long: " + getProperty(key), e);
			System.exit(1);
			return 0;
		}
	}
}