package org.telegram.mtproto.proxy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Simple class for send/receive data to mtproto-proxy
 *
 * @author ait
 */
public class SimpleTcpConnection {

    private final Socket socket;
    private final ProxyObfuscator proxyContext;

    public SimpleTcpConnection(String address, int port, ProxyObfuscator proxyContext) throws IOException {
        socket = new Socket(address, port);
        socket.setKeepAlive(true);
        socket.setTcpNoDelay(true);
        this.proxyContext = proxyContext;
    }

    public InputStream executeMetod(byte[] request) throws IOException {
        writeMesage(request);
        return readMessage();
    }

    private void writeMesage(byte[] request) throws IOException {
        ByteArrayOutputStream tempBuffer = new ByteArrayOutputStream();
        if (request.length / 4 >= 0x7F) {
            int len = request.length / 4;
            tempBuffer.write(0x7F);
            tempBuffer.write(len & 0xFF);
            tempBuffer.write((len >> 8) & 0xFF);
            tempBuffer.write((len >> 16) & 0xFF);
        } else {
            tempBuffer.write(request.length / 4);
        }
        tempBuffer.write(request);

        request = tempBuffer.toByteArray();
        if (proxyContext != null) {
            request = proxyContext.obfuscate(request);
        }

        OutputStream out = socket.getOutputStream();
        out.write(request);
        out.flush();
    }

    private InputStream readMessage() throws IOException {
        InputStream is = socket.getInputStream();

        ByteArrayOutputStream responseBuffer = new ByteArrayOutputStream();
        responseBuffer.write(is.read());
        byte[] remainder = new byte[is.available()];
        is.read(remainder);
        responseBuffer.write(remainder);

        byte[] response = responseBuffer.toByteArray();
        if (proxyContext != null) {
            proxyContext.unobfuscate(response);
        }
        return new ByteArrayInputStream(response);
    }

}
