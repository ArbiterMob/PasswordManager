package org.arbitermob.digests;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.arbitermob.util.Utils;

public class PBKDF2Wrapper {
	private int iterations;
	private SecretKeyFactory skf;
	
	public PBKDF2Wrapper(String algorithm, int iterations) throws NoSuchAlgorithmException {
		this.skf = SecretKeyFactory.getInstance(algorithm);
		this.iterations = iterations;
	}
	
	public byte[] generatePasswordHash(byte[] password, byte[] salt, int key_len) throws InvalidKeySpecException {
		char[] charArray = new String(password, StandardCharsets.UTF_8).toCharArray();
		PBEKeySpec spec = new PBEKeySpec(charArray, salt, iterations, key_len);
		byte[] hash = skf.generateSecret(spec).getEncoded();
		spec.clearPassword(); // clear password from memory
		return hash;
	}
	
	public String formatStoredHash(byte[] raw, byte[] salt, int bitLength) throws InvalidKeySpecException {
	    return iterations + ":" + Utils.toHexString(salt) + ":" + Utils.toHexString(raw);
	}
	/*
	public static boolean validatePassword(byte[] originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String[] parts = storedPassword.split(":");
		int iterations = Integer.parseInt(parts[0]);
		byte[] salt = Utils.fromHexString(parts[1]);
		byte[] hash = Utils.fromHexString(parts[2]);
		
		char[] charArray = new String(originalPassword, StandardCharsets.UTF_8).toCharArray();
		
		PBEKeySpec spec = new PBEKeySpec(charArray, salt, iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] testHash = skf.generateSecret(spec).getEncoded();
		
		int diff = hash.length ^ testHash.length;
		for(int i = 0; i < hash.length && i < testHash.length; i++) {
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String password = "Hello!";
		int iterations = 600000;
		String email = "something@gmail.com";
		
		PBKDF2Wrapper wr = new PBKDF2Wrapper(iterations, Utils.toByteArray(email));
		String hashKey = wr.generatePasswordHash(password.toCharArray());
		System.out.println(hashKey);
		
		System.out.println(PBKDF2Wrapper.validatePassword(password, hashKey));
		System.out.println(PBKDF2Wrapper.validatePassword("Hello1", hashKey));
	}
	*/
	
}
