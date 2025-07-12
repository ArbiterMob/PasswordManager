package org.arbitermob.digests;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestWrapper {
	private final MessageDigest md;
	
	/*
	 * Given the hashing algorithm, sets the md varaiable to be an instance
	 * of MessageDigest
	 */
	public MessageDigestWrapper(String algorithm) throws NoSuchAlgorithmException {
		this.md = MessageDigest.getInstance(algorithm);
	}
	
	/*
	 * Given an array of bytes, updates the input buffer and computes the
	 * digest
	 */
	public byte[] computeDigest(byte[] input) {
		md.update(input);
		return md.digest();
	}
	
	/*
	 * Given a byte, this method computes its digest
	 */
	public byte[] computeDigest(byte input) {
		md.update(input);
		return md.digest();
	}
}
