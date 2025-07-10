package ciphers;

import util.Utils;
import prngs.SecureRandomWrapper;

import javax.crypto.*;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class CipherWrapper {
	private static int key_size;
	private Cipher cipher;
	private SecretKey sk;
	
	/*
     * Given a transformation (example: "AES/OFB/PKCS5Padding"), the function to be passed to the KeyGenerator object keyGenAlgo (example: "AES"),
     * and a SecureRandomWrapper object:
     * - Calls the computeSecretKey function to generate and initialize a symmetric key.
     * - Initializes the cipher variable with an instance retrieved using the correct transformation.
     */
	protected CipherWrapper(String transformation, String keyGenAlgo, SecureRandomWrapper srw, int key_size) throws Exception {
		CipherWrapper.key_size = key_size;
		this.sk = computeSecretKey(keyGenAlgo, srw.getSecureRandom());
		this.cipher = Cipher.getInstance(transformation);
	}
	
	/*
     * Given the keyGen algorithm, and a SecureRandom instance, computes a secret key using the key_size and returns it.
     */
	private static SecretKey computeSecretKey(String keyGenAlgo, SecureRandom sr) throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance(keyGenAlgo);
		keyGen.init(key_size, sr);
		return keyGen.generateKey();
	}
	
	/*
     * Encryption method for ECB that does not require additional parameters.
     * Encrypts a plaintext using the previously computed secret key.
     */
    protected byte[] encrypt(String plaintext) throws Exception {
    	this.cipher.init(Cipher.ENCRYPT_MODE, this.sk);
    	return this.cipher.doFinal(Utils.toByteArray(plaintext));
    }
    
    /*
     * Encryption method for modes of operations that do require additional parameters.
     * Encrypts a plaintext using the previously computed secret key.
     */
    protected byte[] encrypt(String plaintext, AlgorithmParameterSpec spec) throws Exception {
    	this.cipher.init(Cipher.ENCRYPT_MODE, this.sk, spec);
    	return this.cipher.doFinal(Utils.toByteArray(plaintext));
    }
    
    /*
     * Encryption method for AEAD ciphers (respect the order of the following requests).
     * - Updates the inner buffer with additional data.
     * - Encrypts a plaintext using the previously computed secret key.
     */
    protected byte[] encrypt(String plaintext, String additionalData, AlgorithmParameterSpec spec) throws Exception {

    	this.cipher.init(Cipher.ENCRYPT_MODE, this.sk, spec);
    	this.cipher.updateAAD(additionalData.getBytes());
    	return this.cipher.doFinal(Utils.toByteArray(plaintext));
    }
    
    /*
     * Decryption method for ECB that does not require additional parameters.
     * Decrypts a ciphertext using the previously computed secret key.
     */
    protected String decrypt(byte[] ciphertext) throws Exception {	
    	this.cipher.init(Cipher.DECRYPT_MODE, this.sk);
    	return new String(this.cipher.doFinal(ciphertext));
    }

    /*
     * Decryption method for modes of operations that do require additional parameters.
     * Decrypts a ciphertext using the previously computed secret key.
     */
    protected String decrypt(byte[] ciphertext, AlgorithmParameterSpec spec) throws Exception {
    	this.cipher.init(Cipher.DECRYPT_MODE, this.sk, spec);
    	return new String(this.cipher.doFinal(ciphertext));
    }

    /*
     * Decryption method for AEAD ciphers (respect the order of the following requests).
     * - Updates the inner buffer with additional data.
     * - Decrypts a ciphertext using the previously computed secret key.
     * Hint: to convert a byte array into a string use the Utils static class.
     */
    protected String decrypt(byte[] ciphertext, String additionalData, AlgorithmParameterSpec spec) throws Exception {

    	this.cipher.init(Cipher.DECRYPT_MODE, this.sk, spec);
    	this.cipher.updateAAD(additionalData.getBytes());
    	return new String(this.cipher.doFinal(ciphertext));

    }
}