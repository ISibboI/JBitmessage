package sibbo.bitmessage.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.BaseMessage;
import sibbo.bitmessage.network.protocol.NodeServicesMessage;
import sibbo.bitmessage.network.protocol.ParsingException;
import sibbo.bitmessage.network.protocol.SimpleNetworkAddressMessage;
import sibbo.bitmessage.network.protocol.VersionMessage;

public class NetworkTest {
	private static final Logger LOG = Logger.getLogger(NetworkTest.class
			.getName());

	public static void main(String[] args) throws UnknownHostException,
			IOException, ParsingException {
		Socket s = new Socket("localhost", 8444);
		InputStream in = s.getInputStream();
		OutputStream out = s.getOutputStream();

		NodeServicesMessage services = new NodeServicesMessage(
				NodeServicesMessage.NODE_NETWORK);
		SimpleNetworkAddressMessage sender = new SimpleNetworkAddressMessage(
				services, InetAddress.getByName("localhost"), 8443);
		SimpleNetworkAddressMessage receiver = new SimpleNetworkAddressMessage(
				services, InetAddress.getByName("192.168.0.104"), 8444);

		BaseMessage b = new BaseMessage(new VersionMessage(services,
				System.currentTimeMillis() / 1000, receiver, sender, 0,
				"/JBitmessage:0.0.1/", new long[] { 1 }));

		out.write(b.getBytes());

		BaseMessage answer = new BaseMessage(in, 10 * 1024 * 1024);
		System.out.println(answer.getCommand());

		answer = new BaseMessage(in, 10 * 1024 * 1024);
		System.out.println(answer.getCommand());

		VersionMessage remoteVersion = (VersionMessage) answer.getPayload();
		System.out.println("User Agent: " + remoteVersion.getUserAgent());
		System.out.println("Streams: "
				+ Arrays.toString(remoteVersion.getStreams()));
		System.out.println("Nonce: " + remoteVersion.getNonce());
	}
}