package org.arbitermob.digests;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.arbitermob.util.Utils;

public class MacWrapper {
	private SecretKeySpec skp;
	private Mac mac;
	
	public MacWrapper(byte[] key, String algorithm) throws NoSuchAlgorithmException {
		this.skp = new SecretKeySpec(key, algorithm);
		this.mac = Mac.getInstance(algorithm);
	}
	
	public MacWrapper(SecretKeySpec spec, String algorithm) throws NoSuchAlgorithmException {
		this.skp = spec;
		this.mac = Mac.getInstance(algorithm);
	}
	
	public String generateHmac(String data) throws InvalidKeyException {
		mac.reset();
		mac.init(skp);
		return Utils.toHexString(mac.doFinal(data.getBytes()));
	}
	
	public static boolean validateHmac(String key, String algorithm, String originalData, String storedMac) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec spec = new SecretKeySpec(key.getBytes(), algorithm);
		Mac mac = Mac.getInstance(algorithm);
		mac.init(spec);
		byte[] testHash = mac.doFinal(originalData.getBytes());
		byte[] hash = Utils.fromHexString(storedMac);
		
		int diff = hash.length ^ testHash.length;
		for(int i = 0; i < hash.length && i < testHash.length; i++) {
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}
	
}
