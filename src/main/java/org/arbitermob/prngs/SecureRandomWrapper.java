package org.arbitermob.prngs;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomWrapper {
	private final SecureRandom sr;
	
	/*
	 * Given a PRNG algorithm, sets the sr variable to be an instance of 
	 * SecureRandom.
	 */
	public SecureRandomWrapper(String algorithm) throws NoSuchAlgorithmException {
		this.sr = SecureRandom.getInstance(algorithm);
	}
	
	/*
	 * Given a seed, this method changes the seed of the sr variable.
	 */
	public void changeSeed(int seed) {
		this.sr.setSeed(seed);
	}
	
	/*
	 * Retrieves a random integer from the nested SecureRandom variable.
	 */
	public int getRandomInt() {
		return this.sr.nextInt();
	}
	
	// To be used in ciphers
	/*
	 * Given a byte array in input, it fills it with random values.
	 */
	public void fillByteArray(byte[] input) {
		this.sr.nextBytes(input);
	}
	
	/*
	 * Getter method to retrieve the nested SecureRandom variable.
	 */
	public SecureRandom getSecureRandom() {
		return this.sr;
	}
}
