package sibbo.bitmessage.test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.logging.Logger;

import sibbo.bitmessage.network.protocol.BaseMessage;
import sibbo.bitmessage.network.protocol.GetdataMessage;
import sibbo.bitmessage.network.protocol.InvMessage;
import sibbo.bitmessage.network.protocol.MessageFactory;
import sibbo.bitmessage.network.protocol.NodeServicesMessage;
import sibbo.bitmessage.network.protocol.ParsingException;
import sibbo.bitmessage.network.protocol.SimpleNetworkAddressMessage;
import sibbo.bitmessage.network.protocol.V1MessageFactory;
import sibbo.bitmessage.network.protocol.VersionMessage;

public class NetworkTest {
	private static final Logger LOG = Logger.getLogger(NetworkTest.class.getName());

	public static void main(String[] args) throws UnknownHostException, IOException, ParsingException,
			InterruptedException {
		MessageFactory factory = new V1MessageFactory();
		System.out.println("local protocol: " + VersionMessage.PROTOCOL_VERSION);
		Socket s = new Socket("141.134.180.7", 8444);
		InputStream in = s.getInputStream();
		OutputStream out = s.getOutputStream();

		NodeServicesMessage services = new NodeServicesMessage(factory, NodeServicesMessage.NODE_NETWORK);
		SimpleNetworkAddressMessage sender = new SimpleNetworkAddressMessage(services,
				InetAddress.getByName("localhost"), 8443, factory);
		SimpleNetworkAddressMessage receiver = new SimpleNetworkAddressMessage(services,
				InetAddress.getByName("192.168.0.104"), 8444, factory);

		BaseMessage b = new BaseMessage(new VersionMessage(services, System.currentTimeMillis() / 1000, receiver,
				sender, 62256750, "/JBitmessage:0.0.1/", new long[] { 1 }, factory), factory);

		out.write(b.getBytes());
		out.flush();

		Thread.sleep(2000);

		BaseMessage answer = new BaseMessage(in, 10 * 1024 * 1024, factory);
		System.out.println(answer.getCommand());

		answer = new BaseMessage(in, 10 * 1024 * 1024, factory);
		System.out.println(answer.getCommand());

		VersionMessage remoteVersion = (VersionMessage) answer.getPayload();
		System.out.println("User Agent: " + remoteVersion.getUserAgent());
		System.out.println("Streams: " + Arrays.toString(remoteVersion.getStreams()));
		System.out.println("Nonce: " + remoteVersion.getNonce());

		BaseMessage inv = new BaseMessage(in, 10 * 1024 * 1024, factory);
		System.out.println(inv.getCommand());

		Thread.sleep(10_000);

		BaseMessage getDataMessage = new BaseMessage(new GetdataMessage(
				((InvMessage) inv.getPayload()).getInventoryVectors(), factory), factory);
		out.write(getDataMessage.getBytes());
		out.flush();

		while (true) {
			answer = new BaseMessage(in, 10 * 1024 * 1024, factory);
			System.out.println(answer.getCommand());

			if (answer.getCommand().equals("msg")) {
				File f = new File("/home/sibbo/msg");

				if (f.exists())
					f.delete();

				f.createNewFile();

				new FileOutputStream(f).write(answer.getPayload().getBytes());
				return;
			}
		}
	}
}