package sibbo.bitmessage.network;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

public class LoggingInputStream extends InputStream {
	private static final Logger LOG = Logger.getLogger(LoggingInputStream.class
			.getName());

	private InputStream in;

	private OutputStream out;

	public LoggingInputStream(InputStream in) throws FileNotFoundException {
		this.in = in;
		out = new FileOutputStream(new File("input"));
	}

	@Override
	public int read() throws IOException {
		int i = in.read();
		out.write(i);
		out.flush();
		return i;
	}

	@Override
	public int read(byte[] b, int offset, int length) throws IOException {
		int i = in.read(b, offset, length);
		out.write(b, offset, i);
		out.flush();
		return i;
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}
}