package digests;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HKDFWrapper {
	private Mac mac;
	
	public HKDFWrapper(String algorithm) throws NoSuchAlgorithmException {
		this.mac = Mac.getInstance(algorithm);
	}
	
	public SecretKey createSecretKey(byte[] rawKeyMaterial) {
		if (rawKeyMaterial == null || rawKeyMaterial.length <= 0) {
			return null;
		}
		return new SecretKeySpec(rawKeyMaterial, mac.getAlgorithm());
	}
	
	public byte[] extract(byte[] salt, byte[] inputKeyingMaterial) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey saltKey;
		if (salt == null) {
			saltKey = createSecretKey(new byte[mac.getMacLength()]);
		} else {
			saltKey = createSecretKey(salt);
		}
		
		if (inputKeyingMaterial == null || inputKeyingMaterial.length <= 0) {
			throw new IllegalArgumentException("provided inputKeyingMaterial must be at least of size 1 and not null");
		}
		
		Mac mac1 = Mac.getInstance(mac.getAlgorithm());
		mac1.init(saltKey);
		return mac1.doFinal(inputKeyingMaterial);
	}
	
	public byte[] expand(byte[] pseudoRandomKey, byte[] info, int outLengthBytes) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey prk = createSecretKey(pseudoRandomKey);
		
		if (outLengthBytes <= 0) {
			throw new IllegalArgumentException("provided pseudoRandomKey must not be null");
		}
		
		Mac hmacHasher = Mac.getInstance(mac.getAlgorithm());
		hmacHasher.init(prk);
		
		if (info == null) {
			info = new byte[0];
		}
		
		/*
        The output OKM is calculated as follows:
          N = ceil(L/HashLen)
          T = T(1) | T(2) | T(3) | ... | T(N)
          OKM = first L bytes of T
        where:
          T(0) = empty string (zero length)
          T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
          T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
          T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
          ...
         */
		
		byte[] blockN = new byte[0];

        int iterations = (int) Math.ceil(((double) outLengthBytes) / ((double) hmacHasher.getMacLength()));

        if (iterations > 255) {
            throw new IllegalArgumentException("out length must be maximal 255 * hash-length; requested: " + outLengthBytes + " bytes");
        }

        ByteBuffer buffer = ByteBuffer.allocate(outLengthBytes);
        int remainingBytes = outLengthBytes;
        int stepSize;

        for (int i = 0; i < iterations; i++) {
            hmacHasher.update(blockN);
            hmacHasher.update(info);
            hmacHasher.update((byte) (i + 1));

            blockN = hmacHasher.doFinal();

            stepSize = Math.min(remainingBytes, blockN.length);

            buffer.put(blockN, 0, stepSize);
            remainingBytes -= stepSize;
        }

        return buffer.array();
	}
}
