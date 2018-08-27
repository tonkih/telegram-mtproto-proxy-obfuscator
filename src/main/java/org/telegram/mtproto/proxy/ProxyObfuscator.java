package org.telegram.mtproto.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.telegram.mtproto.proxy.secure.AesCtr;
import static org.telegram.mtproto.proxy.util.Utils.*;

public class ProxyObfuscator {

    private static final int KEY_LEN = 32;
    private static final int IV_LEN = 16;

    private static final int RANDOM_BUFFER_LEN = 64;

    private final byte[] secret;
    private AesCtr encoder;
    private AesCtr decoder;

    private byte[] key;
    private byte[] iv;

    private byte[] decryptKey;
    private byte[] decryptIv;

    private boolean isFirst = true;

    public ProxyObfuscator(String address, int port, String secret) {
        this.secret = hexStringToByteArray(secret);
    }

    public byte[] obfuscate(byte[] request) throws IOException {
        if (isFirst) {
            byte[] obfuscatedInfo = getRandomBuffer();
            encoder.processBuffer(request);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(obfuscatedInfo);
            out.write(request);
            isFirst = false;
            return out.toByteArray();
        } else {
            encoder.processBuffer(request);
            return request;
        }
    }

    public void unobfuscate(byte[] response) {
        decoder.processBuffer(response);
    }

    /**
     * Get byte array with settings for telegram mtproto proxy
     *
     * @return
     */
    private byte[] getRandomBuffer() {
        byte[] randomBuf = nextRandomBytes(RANDOM_BUFFER_LEN);
        while (true) {
            int val = (randomBuf[3] << 24) | (randomBuf[2] << 16) | (randomBuf[1] << 8) | (randomBuf[0]);
            int val2 = (randomBuf[7] << 24) | (randomBuf[6] << 16) | (randomBuf[5] << 8) | (randomBuf[4]);
            if (randomBuf[0] != 0xef
                    && val != 0x44414548
                    && val != 0x54534f50
                    && val != 0x20544547
                    && val != 0x4954504f
                    && val != 0xeeeeeeee
                    && val2 != 0x00000000) {
                randomBuf[56] = randomBuf[57] = randomBuf[58] = randomBuf[59] = (byte) 0xef;
                int datacenterId = 2;
                // Add datacenter id
                randomBuf[60] = (byte) (datacenterId & 0xff);
                // Add protocol
                randomBuf[61] = (byte) ((datacenterId >> 8) & 0xff);
                break;
            }
            changeRandomBytes(randomBuf);
        }

        if (key == null) {
            key = new byte[KEY_LEN];
            for (int i = 8; i < 40; i++) {
                key[i - 8] = randomBuf[i];
            }
            iv = new byte[IV_LEN];
            for (int i = 40; i < 56; i++) {
                iv[i - 40] = randomBuf[i];
            }
        }

        byte[] tempRandomBuffer = new byte[randomBuf.length];
        System.arraycopy(randomBuf, 0, tempRandomBuffer, 0, tempRandomBuffer.length);

        encoder = AesCtr.fromKeyAndSecret(key, iv, secret);
        encoder.processBuffer(tempRandomBuffer);

        System.arraycopy(tempRandomBuffer, 56, randomBuf, 56, randomBuf.length - 56);
        System.arraycopy(key, 0, randomBuf, 8, key.length);
        System.arraycopy(iv, 0, randomBuf, 40, iv.length);

        if (decryptKey == null) {
            decryptIv = new byte[IV_LEN];
            for (int i = 8; i < 24; i++) {
                decryptIv[i - 8] = randomBuf[i];
            }
            decryptKey = new byte[KEY_LEN];
            for (int i = 24; i < 56; i++) {
                decryptKey[i - 24] = randomBuf[i];
            }
            reverseByteArray(decryptIv);
            reverseByteArray(decryptKey);
            decoder = AesCtr.fromKeyAndSecret(decryptKey, decryptIv, secret);
        }

        return randomBuf;
    }
}
