package digests;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import util.Utils;

public class PBKDF2Wrapper {
	private int iterations;
	private byte[] salt;
	private SecretKeyFactory skf;
	
	public PBKDF2Wrapper(int iterations, byte[] salt) throws NoSuchAlgorithmException {
		this.skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		this.salt = salt;
		this.iterations = iterations;
	}
	
	public String generatePasswordHash(char[] password) throws InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
		byte[] hash = skf.generateSecret(spec).getEncoded();
		spec.clearPassword(); // clear password from memory
		return iterations + ":" + Utils.toHexString(salt) + ":" + Utils.toHexString(hash);
	}
	
	public static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
		String[] parts = storedPassword.split(":");
		int iterations = Integer.parseInt(parts[0]);
		byte[] salt = Utils.fromHexString(parts[1]);
		byte[] hash = Utils.fromHexString(parts[2]);
		
		PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] testHash = skf.generateSecret(spec).getEncoded();
		
		int diff = hash.length ^ testHash.length;
		for(int i = 0; i < hash.length && i < testHash.length; i++) {
			diff |= hash[i] ^ testHash[i];
		}
		return diff == 0;
	}
	
	/*
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
