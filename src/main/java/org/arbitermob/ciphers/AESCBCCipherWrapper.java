package org.arbitermob.ciphers;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.arbitermob.prngs.SecureRandomWrapper;

public class AESCBCCipherWrapper extends CipherWrapper {
	// This class extends the CipherWrapper class to implement methods that are specific for AES in CBC mode.
    // Methods are now public and can be called outside the class.
	
	/*
     * Initializes the superclass with correct algorithms.
     */
    public AESCBCCipherWrapper(SecureRandomWrapper srw, int key_size) throws Exception {
    	super("AES/CBC/PKCS5Padding", "AES", srw, key_size);
    }
    
    /*
     * Generates the correct AlgorithmParameterSpec before calling the right superclass method to encrypt a plaintext.
     */
    public byte[] encrypt(byte[] plaintext, byte[] iv, SecretKeySpec spec) throws Exception {
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    	return super.encrypt(plaintext, ivParameterSpec, spec);
    }
    
    /*
     * Generates the correct AlgorithmParameterSpec before calling the right superclass method to decrypt a plaintext.
     */
    public byte[] decrypt(byte[] ciphertext, byte[] iv, SecretKeySpec spec) throws Exception {
    	IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);    
    	return super.decrypt(ciphertext, ivParameterSpec, spec);
    }
}
