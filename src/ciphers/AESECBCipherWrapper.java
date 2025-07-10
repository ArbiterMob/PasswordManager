package ciphers;

import prngs.SecureRandomWrapper;

public class AESECBCipherWrapper extends CipherWrapper {
	// This class extends the CipherWrapper class to implement methods that are specific for AES in ECB mode.
    // Methods are now public and can be called outside the class.

    /*
     * Initializes the superclass with correct algorithms.
     */
    public AESECBCipherWrapper(SecureRandomWrapper srw, int key_size) throws Exception {
    	super("AES/ECB/PKCS5Padding", "AES", srw, key_size);
    }

    /*
     * Calls the right superclass method to encrypt a plaintext.
     */
    public byte[] encrypt(String plaintext) throws Exception {
    	return super.encrypt(plaintext);
    }

    /*
     * Calls the right superclass method to decrypt a plaintext using AES in ECB mode.
     */
    public String decrypt(byte[] ciphertext) throws Exception {
    	return super.decrypt(ciphertext);
    }
}
