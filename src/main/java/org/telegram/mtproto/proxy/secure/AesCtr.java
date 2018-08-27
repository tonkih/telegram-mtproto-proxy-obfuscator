package org.telegram.mtproto.proxy.secure;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static org.telegram.mtproto.proxy.util.Utils.copyByteArray;

public class AesCtr {

    private final AESFastEngine engine;
    private final byte[] counter, gamma;
    private int gammaPos;

    public AesCtr(byte[] key, byte[] iv) {
        engine = new AESFastEngine();
        engine.init(true, key);

        counter = new byte[16];
        gamma = new byte[16];

        System.arraycopy(iv, 0, counter, 0, 16);
        generateGamma();
    }

    private void generateGamma() {
        engine.processBlock(counter, 0, gamma, 0);
        gammaPos = 0;

        for (int i = 15; i >= 0; i--) {
            counter[i]++;

            if (counter[i] != 0) {
                break;
            }
        }
    }

    public byte nextGamma() {
        byte r = gamma[gammaPos++];

        if (gammaPos >= 16) {
            generateGamma();
        }

        return r;
    }

    public void skipGamma(int n) {
        for (int i = 0; i < n; i++) {
            nextGamma();
        }
    }

    public void processBuffer(byte[] x) {
        processBuffer(x, 0, x.length);
    }

    public void processBuffer(byte[] x, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            x[i] = (byte) (x[i] ^ nextGamma());
        }
    }

    public static AesCtr fromKeyAndSecret(byte[] primaryKey, byte[] iv, byte[] secret) {
        byte[] key = copyByteArray(primaryKey);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(key);
            md.update(secret);
            md.digest(key, 0, key.length);
        } catch (NoSuchAlgorithmException | DigestException e) {
            throw new RuntimeException("Failed to perform SHA-256 on key and secret", e);
        }
        return new AesCtr(key, iv);
    }

}
