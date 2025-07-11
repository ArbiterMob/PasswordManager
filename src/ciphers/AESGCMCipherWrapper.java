package ciphers;

import prngs.SecureRandomWrapper;
import javax.crypto.spec.GCMParameterSpec;

public class AESGCMCipherWrapper extends CipherWrapper{
	// AES-GCM is an AEAD cipher and requires the user to input the length of the Message Authentication Code.
    private final int MAC_LENGTH = 128;
    
 // This class extends the CipherWrapper class to implement methods that are specific for AES in GCM mode.
    // Methods are now public and can be called outside the class.

    /*
     * Initializes the superclass with correct algorithms.
     */
    public AESGCMCipherWrapper(SecureRandomWrapper srw, int key_size) throws Exception {
    	super("AES/GCM/NoPadding", "AES", srw, key_size);
    }

    /*
     * Generates the correct AlgorithmParameterSpec before calling the right superclass method to encrypt a plaintext.
     */
    public byte[] encrypt(byte[] plaintext, String additionalData, byte[] iv) throws Exception {

    	GCMParameterSpec spec = new GCMParameterSpec(MAC_LENGTH, iv);
    	return super.encrypt(plaintext, additionalData, spec);

    }

    /*
     * Generates the correct AlgorithmParameterSpec before calling the right superclass method to decrypt a plaintext.
     * Total suggested lines: 2/3.
     */
    public String decrypt(byte[] ciphertext, String additionalData, byte[] iv) throws Exception {

    	GCMParameterSpec spec = new GCMParameterSpec(MAC_LENGTH, iv);
    	return super.decrypt(ciphertext, additionalData, spec);

    }
}
