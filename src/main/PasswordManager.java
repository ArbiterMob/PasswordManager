package main;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import ciphers.AESCBCCipherWrapper;
import digests.HKDFWrapper;
import digests.PBKDF2Wrapper;
import prngs.SecureRandomWrapper;
import util.Utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder; 

public class PasswordManager {
	private static final byte[] info = Utils.toByteArray("Key Expansion");
	private static final int iterations = 600000;
	private static final int key_len = 256;
	
	private static final String userFile = ".currUser.json";
	private static final String vaultEntriesFile = ".vaultEntries.json";
	
	public PasswordManager() {
		super();
	}
	
	public void register(String[] args) {
		if (new File(userFile).exists()) {
			System.out.println("User is alredy registered. If you forgot the password, you may reset the PasswordManager (res)");
			return;
		}
		
		// Read email and password from stdin
		Console cnsl = System.console();
		if (cnsl == null) {
			System.out.println("No console available");
			return;
		}
		
		String saltEmail = cnsl.readLine("Enter email: ");
		byte[] saltEmailByte = Utils.toByteArray(saltEmail);
		
		char[] password = cnsl.readPassword("Enter password: ");
		String pwdString = new String(password);
		byte[] passwordByte = Utils.toByteArray(pwdString);
		
		try {
			// Create masterKey (PBKDF2 - salt: email, payload: password)
			PBKDF2Wrapper  pbkdf2 = new PBKDF2Wrapper("PBKDF2WithHmacSHA256", iterations);
			byte[] masterKey = pbkdf2.generatePasswordHash(passwordByte, saltEmailByte, key_len);
			
			// Create masterPasswordHash (PBKDF2 - salt: password, payload: masterKey)
			byte[] masterPasswordHash = pbkdf2.generatePasswordHash(masterKey, passwordByte, key_len);
			String masterPasswordHashStore = pbkdf2.formatStoredHash(masterPasswordHash, passwordByte, iterations);
			
			// Create stretchedMasterKey (HKDF - salt: email, payload (ikm): masterKey, info: info)
			HKDFWrapper hkdf = new HKDFWrapper("HmacSHA256");
			byte[] stretchedMasterKey = hkdf.extractAndExpand(saltEmailByte, masterKey, info, 64);
			
			// Generate symmetricKeyWithMacKey of 512 bit and an initVector of 128 bit
			SecureRandomWrapper srw = new SecureRandomWrapper("SHA1PRNG");
			byte[] symmetricKeyWithMacKey = new byte[64];
			srw.fillByteArray(symmetricKeyWithMacKey);
			
			byte[] initVector = new byte[16];
			srw.fillByteArray(initVector);
			
			// AES256-CBC-HMAC-SHA256 with initVector previously initialised
			// Create protectedSymmetricKey (IV || symmetricKeyWithMacKey encrypted with AES256-CBC || HMAC-SHA256 of the symmetricKeyWithMacKey encrypted)
			byte[] protectedSymmetricKey = encryptWithAES256_CBC_HMAC_SHA256(stretchedMasterKey, symmetricKeyWithMacKey, initVector, srw);
			
			// Create User
			User user = new User(saltEmail, masterPasswordHashStore, Utils.toHexString(protectedSymmetricKey));
			
			// Save User in JSON format in a file
			GsonBuilder builder = new GsonBuilder(); 
		    builder.setPrettyPrinting();
		      
			Gson gson = builder.create(); 
			String jsonString = gson.toJson(user);
			
			File myFile = new File(userFile);
			myFile.createNewFile();
			FileWriter writer = new FileWriter(myFile);
			writer.write(jsonString);
			writer.close();
			
			// Final Output
			System.out.println("User registered with success! If you forget the password, you may want to reset the PasswordManager");
			
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}
	
	public void add(String[] args) {
		GsonBuilder builder = new GsonBuilder(); 
		builder.setPrettyPrinting();		      
		Gson gson = builder.create(); 
		User user = loadUser(gson);
		
		// Read email and password from stdin
		Console cnsl = System.console();
		if (cnsl == null) {
			System.out.println("No console available");
			return;
		}
		
		String saltEmail = user.getSaltEmail();
		byte[] saltEmailByte = Utils.toByteArray(saltEmail);
		
		char[] password = cnsl.readPassword("Enter password: ");
		String pwdString = new String(password);
		byte[] passwordByte = Utils.toByteArray(pwdString);
		
		try {
			
			// Validate Password
			PBKDF2Wrapper  pbkdf2 = new PBKDF2Wrapper("PBKDF2WithHmacSHA256", iterations);
			byte[] masterKey = validatePassword(passwordByte, saltEmailByte, user, pbkdf2);
				
			// Get the symmetricKeyWithMacKey of 512 bit
			SecureRandomWrapper srw = new SecureRandomWrapper("SHA1PRNG");
			byte[] protectedSymmetricKey = Utils.fromHexString(user.getProtectedSymmetricKey());
			byte[] symmetricKeyWithMacKey = getSymmetricKeyWithMacKey(saltEmailByte, masterKey, protectedSymmetricKey, srw);
			
			// Input the user for the specific vault data
			System.out.println("Initializing Vauld Data");
			String nameService = cnsl.readLine("Enter name of the Service: ");
			String emailService = cnsl.readLine("Enter email or ID for the Service: ");
			char[] pwdService = cnsl.readPassword("Enter password for the Service: ");
			String pwdServiceString = new String(pwdService);
			
			Map<String,String> record = new HashMap<>();
			//record.put("nameService", nameService);
			record.put("emailService", emailService);
			record.put("pwdService", pwdServiceString);
			String vaultEntryMap = gson.toJson(record);
			byte[] vaultEntryBytes = Utils.toByteArray(vaultEntryMap);
			byte[] initVector = new byte[16];
			srw.fillByteArray(initVector);
			
			// may want to create a cipherKey for the specific VaultEntry
			
			// AES256-CBC-HMAC-SHA256 with initVector previously initialised
			byte[] protectedVaultEntry = encryptWithAES256_CBC_HMAC_SHA256(symmetricKeyWithMacKey, vaultEntryBytes, initVector, srw);
			
			// Save VaultEntry in a file
			VaultEntry ve = new VaultEntry(nameService, Utils.toHexString(protectedVaultEntry));
			String vaultEntry = gson.toJson(ve);
			
			File myFile = new File(vaultEntriesFile);
			boolean isNew = !myFile.exists();
			RandomAccessFile raf = new RandomAccessFile(myFile, "rw");
			if (isNew) {
				raf.writeBytes("[" + vaultEntry + "]");
			} else {
				raf.seek(raf.length() - 1);
				raf.writeBytes("," + vaultEntry + "]");
			}
			raf.close();
						
			// Final Output
			System.out.println("VaultEntry added with success!");
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}
	
	public void update(String[] args) {
		GsonBuilder builder = new GsonBuilder(); 
		builder.setPrettyPrinting();		      
		Gson gson = builder.create(); 
		User user = loadUser(gson);
		
		// Read email and password from stdin
		Console cnsl = System.console();
		if (cnsl == null) {
			System.out.println("No console available");
			return;
		}
		
		String saltEmail = user.getSaltEmail();
		byte[] saltEmailByte = Utils.toByteArray(saltEmail);
		
		char[] password = cnsl.readPassword("Enter password: ");
		String pwdString = new String(password);
		byte[] passwordByte = Utils.toByteArray(pwdString);
		
		try {
			// Validate Password
			PBKDF2Wrapper  pbkdf2 = new PBKDF2Wrapper("PBKDF2WithHmacSHA256", iterations);
			byte[] masterKey = validatePassword(passwordByte, saltEmailByte, user, pbkdf2);
							
			// Get the symmetricKeyWithMacKey of 512 bit
			SecureRandomWrapper srw = new SecureRandomWrapper("SHA1PRNG");
			byte[] protectedSymmetricKey = Utils.fromHexString(user.getProtectedSymmetricKey());
			byte[] symmetricKeyWithMacKey = getSymmetricKeyWithMacKey(saltEmailByte, masterKey, protectedSymmetricKey, srw);
			
			// Input the user for the specific vault data
			System.out.println("Initializing Vauld Data");
			String nameService = cnsl.readLine("Enter name of the Service: ");
			
			// Get the specific VaultEntry			
			VaultEntry entry = getVaultEntry(nameService, gson);
			
			// Decrypt using symmetricKeyWithMacKey
			byte[] jsonRecordBytes = decryptWithAES256_CBC_HMAC_SHA256(symmetricKeyWithMacKey, Utils.fromHexString(entry.getProtectedVaultEntry()), srw);
			String jsonRecord = new String(jsonRecordBytes);
			Map<String, String> record = gson.fromJson(jsonRecord, Map.class);
			
			// Input the user for the changes
			String emailService = cnsl.readLine("Enter New email or ID for the Service: ");
			char[] pwdService = cnsl.readPassword("Enter New password for the Service: ");
			String pwdServiceString = new String(pwdService);
			
			record.put("emailService", emailService);
			record.put("pwdService", pwdServiceString);
			
			String vaultEntryMap = gson.toJson(record);
			byte[] vaultEntryBytes = Utils.toByteArray(vaultEntryMap);
			byte[] initVector = new byte[16];
			srw.fillByteArray(initVector);
			
			// AES256-CBC-HMAC-SHA256 with initVector previously initialised
			byte[] protectedVaultEntry = encryptWithAES256_CBC_HMAC_SHA256(symmetricKeyWithMacKey, vaultEntryBytes, initVector, srw);
						
			// Save VaultEntry in a file
			VaultEntry[] entries = getAllVaultEntries(gson);
			for (VaultEntry e : entries) {
				if (e.getNameService().equals(nameService)) {
					e.setProtectedVaultEntry(Utils.toHexString(protectedVaultEntry));
				}
			}
			
			// Update the File
			String vaultEntries = gson.toJson(entries);
						
			File myFile = new File(vaultEntriesFile);
			RandomAccessFile raf = new RandomAccessFile(myFile, "rw");
			raf.setLength(0);
			//raf.seek(0);
			raf.writeBytes(vaultEntries);
			raf.close();
									
			// Final Output
			System.out.println("VaultEntry updated with success!");
			
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}
	
	public void remove(String[] args) {
		GsonBuilder builder = new GsonBuilder(); 
		builder.setPrettyPrinting();	      
		Gson gson = builder.create(); 
		User user = loadUser(gson);
		
		// Read email and password from stdin
		Console cnsl = System.console();
		if (cnsl == null) {
			System.out.println("No console available");
			return;
		}
		
		String saltEmail = user.getSaltEmail();
		byte[] saltEmailByte = Utils.toByteArray(saltEmail);
		
		char[] password = cnsl.readPassword("Enter password: ");
		String pwdString = new String(password);
		byte[] passwordByte = Utils.toByteArray(pwdString);
		
		try {
			// Validate Password
			PBKDF2Wrapper  pbkdf2 = new PBKDF2Wrapper("PBKDF2WithHmacSHA256", iterations);
			validatePassword(passwordByte, saltEmailByte, user, pbkdf2);
						
			// Input the user for the specific vault data
			System.out.println("Getting Vauld Data");
			String nameService = cnsl.readLine("Enter name of the Service that you want to delete: ");
			
			// Remove the specific VaultEntry
			VaultEntry[] entries = removeVaultEntry(nameService, gson);
			
			// Update the File
			String vaultEntries = gson.toJson(entries);
			
			File myFile = new File(vaultEntriesFile);
			RandomAccessFile raf = new RandomAccessFile(myFile, "rw");
			raf.setLength(0);
			//raf.seek(0);
			raf.writeBytes(vaultEntries);
			raf.close();
						
			// Final Output
			System.out.println("VaultEntry removed with success!");
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}
	
	public void get(String[] args) {
		GsonBuilder builder = new GsonBuilder(); 
		builder.setPrettyPrinting();	      
		Gson gson = builder.create(); 
		User user = loadUser(gson);
		
		// Read email and password from stdin
		Console cnsl = System.console();
		if (cnsl == null) {
			System.out.println("No console available");
			return;
		}
		
		String saltEmail = user.getSaltEmail();
		byte[] saltEmailByte = Utils.toByteArray(saltEmail);
		
		char[] password = cnsl.readPassword("Enter password: ");
		String pwdString = new String(password);
		byte[] passwordByte = Utils.toByteArray(pwdString);
		
		try {
			// Validate Password
			PBKDF2Wrapper  pbkdf2 = new PBKDF2Wrapper("PBKDF2WithHmacSHA256", iterations);
			byte[] masterKey = validatePassword(passwordByte, saltEmailByte, user, pbkdf2);
							
			// Get the symmetricKeyWithMacKey of 512 bit
			SecureRandomWrapper srw = new SecureRandomWrapper("SHA1PRNG");
			byte[] protectedSymmetricKey = Utils.fromHexString(user.getProtectedSymmetricKey());
			byte[] symmetricKeyWithMacKey = getSymmetricKeyWithMacKey(saltEmailByte, masterKey, protectedSymmetricKey, srw);
			
			// Input the user for the specific vault data
			System.out.println("Getting Vauld Data");
			String nameService = cnsl.readLine("Enter name of the Service: ");
			
			// Get the specific VaultEntry
			VaultEntry entry = getVaultEntry(nameService, gson);
			
			// Decrypt using symmetricKeyWithMacKey
			byte[] jsonRecordBytes = decryptWithAES256_CBC_HMAC_SHA256(symmetricKeyWithMacKey, Utils.fromHexString(entry.getProtectedVaultEntry()), srw);
			String jsonRecord = new String(jsonRecordBytes);
			Map<String, String> record = gson.fromJson(jsonRecord, Map.class);
			for (Entry<String, String> en : record.entrySet()) {
				System.out.println(en.getKey() + ": " + en.getValue());
			}
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}
	
	public void reset(String[] args) {
		Console cnsl = System.console();
		if (cnsl == null) {
			System.out.println("No console available");
			return;
		}
		
		System.out.println("Are you sure you want to reset the Password Manager?");
		String confirm = cnsl.readLine("y/n: ");
		
		if (confirm.trim().toLowerCase().equals("y")) {
			File user = new File(userFile);
			File vault = new File(vaultEntriesFile);
			
			if (!user.delete()) {
				System.out.println("Failed in deleting the userFile: " + userFile);
				System.exit(1);
			}
			
			if (!vault.delete()) {
				System.out.println("Failed in deleting the vaultEntriesFile: " + vaultEntriesFile);
				System.exit(1);
			}
		}
	}
	
	public byte[] validatePassword(byte[] passwordByte, byte[] saltEmailByte, User user, PBKDF2Wrapper  pbkdf2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		// Validate Password
		byte[] masterKey = pbkdf2.generatePasswordHash(passwordByte, saltEmailByte, key_len);
		
		byte[] masterPasswordHash = pbkdf2.generatePasswordHash(masterKey, passwordByte, key_len);
		byte[] testHash = Utils.fromHexString(user.getMasterPasswordHash().split(":")[2]);
		
		int diff = masterPasswordHash.length ^ testHash.length;
		for(int i = 0; i < masterPasswordHash.length && i < testHash.length; i++) {
			diff |= masterPasswordHash[i] ^ testHash[i];
		}
		if (diff != 0) {
			System.out.println("The password isn't correct!");
			System.exit(1);
		}
		
		return masterKey;
	}
	
	public byte[] getSymmetricKeyWithMacKey(byte[] saltEmailByte, byte[] masterKey, byte[] protectedSymmetricKey, SecureRandomWrapper srw) 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, Exception {
		// Create stretchedMasterKey (HKDF - salt: email, payload (ikm): masterKey, info: info)
		HKDFWrapper hkdf = new HKDFWrapper("HmacSHA256");
		byte[] stretchedMasterKey = hkdf.extractAndExpand(saltEmailByte, masterKey, info, 64);
					
		// Get the symmetricKeyWithMacKey of 512 bit
		byte[] initVector = Arrays.copyOfRange(protectedSymmetricKey, 0, 16);
		byte[] symmetricKeyWithMacKeyEnc = Arrays.copyOfRange(protectedSymmetricKey, 16, protectedSymmetricKey.length - 32);
		byte[] hmacTest = Arrays.copyOfRange(protectedSymmetricKey, protectedSymmetricKey.length - 32, protectedSymmetricKey.length);
					
		byte[] keyEnc = Arrays.copyOfRange(stretchedMasterKey, 0, 32);
		byte[] keyMac = Arrays.copyOfRange(stretchedMasterKey, 32, 64);
		SecretKeySpec encKeySpec = new SecretKeySpec(keyEnc, "AES");
		SecretKeySpec macKeySpec = new SecretKeySpec(keyMac, "HmacSHA256");
					
		// Verify HMAC
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(macKeySpec);
		mac.update(initVector);
		mac.update(symmetricKeyWithMacKeyEnc);
		byte[] hmac = mac.doFinal();

		int diff = hmac.length ^ hmacTest.length;
		for(int i = 0; i < hmac.length && i < hmacTest.length; i++) {
			diff |= hmac[i] ^ hmacTest[i];
		}
		if (diff != 0) {
			System.out.println("The hmac isn't correct!");
			System.exit(1);
		}
					
		// Decrypt
		AESCBCCipherWrapper cipher = new AESCBCCipherWrapper(srw, 256);
		byte[] symmetricKeyWithMacKey = cipher.decrypt(symmetricKeyWithMacKeyEnc, initVector, encKeySpec);
		return symmetricKeyWithMacKey;
	}
	
	public VaultEntry getVaultEntry(String nameService, Gson gson) {
		File myFile = new File(vaultEntriesFile);
		if (!myFile.exists()) {
			System.out.println("User has no Vault entries. To add an entry use the command add");
			System.exit(1);
		}
		Scanner myReader;
		ByteArrayOutputStream out = null;
		String jsonString = "";
		try {
			myReader = new Scanner(myFile);
			out = new ByteArrayOutputStream();
			while (myReader.hasNextLine()) {
				out.write(Utils.toByteArray(myReader.nextLine()));
			}
			jsonString = out.toString();
		}
		catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		VaultEntry[] entries = gson.fromJson(jsonString, VaultEntry[].class);
		VaultEntry entryUser = null;
		for (VaultEntry entry : entries) {
			if (nameService.equals(entry.getNameService())) {
				entryUser = entry;
				break;
			}
		}
		
		if (entryUser == null) {
			System.out.println("Vault Entry not found");
			System.exit(1);
		}
		
		return entryUser;
	}
	
	public VaultEntry[] getAllVaultEntries(Gson gson) {
		File myFile = new File(vaultEntriesFile);
		if (!myFile.exists()) {
			System.out.println("User has no Vault entries. To add an entry use the command add");
			System.exit(1);
		}
		Scanner myReader;
		ByteArrayOutputStream out = null;
		String jsonString = "";
		try {
			myReader = new Scanner(myFile);
			out = new ByteArrayOutputStream();
			while (myReader.hasNextLine()) {
				out.write(Utils.toByteArray(myReader.nextLine()));
			}
			jsonString = out.toString();
		}
		catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		VaultEntry[] entries = gson.fromJson(jsonString, VaultEntry[].class);
		return entries;
	}
	
	public VaultEntry[] removeVaultEntry(String nameService, Gson gson) {
		File myFile = new File(vaultEntriesFile);
		if (!myFile.exists()) {
			System.out.println("User has no Vault entries. To add an entry use the command add");
			System.exit(1);
		}
		Scanner myReader;
		ByteArrayOutputStream out = null;
		String jsonString = "";
		try {
			myReader = new Scanner(myFile);
			out = new ByteArrayOutputStream();
			while (myReader.hasNextLine()) {
				out.write(Utils.toByteArray(myReader.nextLine()));
			}
			jsonString = out.toString();
		}
		catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
		
		VaultEntry[] entries = gson.fromJson(jsonString, VaultEntry[].class);
		VaultEntry[] result = new VaultEntry[entries.length - 1];
		boolean found = false;
		
		int j = 0;
		for (int i = 0; i < entries.length; i++) {
			if (!nameService.equals(entries[i].getNameService())) {
				result[j++] = entries[i];
			} else {
				found = true;
			}
		}
		
		if (!found) {
			System.out.println("Vault Entry not found");
			System.exit(1);
		}
		
		return result;
	}
	
	public byte[] encryptWithAES256_CBC_HMAC_SHA256(byte[] symmetricKeyWithMacKey, byte[] vaultEntryBytes, byte[] initVector, SecureRandomWrapper srw) 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, Exception {
		byte[] keyEnc = Arrays.copyOfRange(symmetricKeyWithMacKey, 0, 32);
		byte[] keyMac = Arrays.copyOfRange(symmetricKeyWithMacKey, 32, 64);
		SecretKeySpec encKeySpec = new SecretKeySpec(keyEnc, "AES");
		SecretKeySpec macKeySpec = new SecretKeySpec(keyMac, "HmacSHA256");
					
		AESCBCCipherWrapper cipher = new AESCBCCipherWrapper(srw, 256);
		byte[] vaultEntryEnc = cipher.encrypt(vaultEntryBytes, initVector, encKeySpec);
		
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(macKeySpec);
		mac.update(initVector);
		mac.update(vaultEntryEnc);
		byte[] hmac = mac.doFinal();
		
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(initVector);
		out.write(vaultEntryEnc);
		out.write(hmac);
		byte[] protectedVaultEntry = out.toByteArray();
		return protectedVaultEntry;
	}
	
	public byte[] decryptWithAES256_CBC_HMAC_SHA256(byte[] symmetricKeyWithMacKey, byte[] dataBytes, SecureRandomWrapper srw) 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, Exception{
		byte[] keyEnc = Arrays.copyOfRange(symmetricKeyWithMacKey, 0, 32);
		byte[] keyMac = Arrays.copyOfRange(symmetricKeyWithMacKey, 32, 64);
		SecretKeySpec encKeySpec = new SecretKeySpec(keyEnc, "AES");
		SecretKeySpec macKeySpec = new SecretKeySpec(keyMac, "HmacSHA256");
		
		// Deconstruct the payload
		byte[] initVector = Arrays.copyOfRange(dataBytes, 0, 16);
		byte[] vaultEntryEnc = Arrays.copyOfRange(dataBytes, 16, dataBytes.length - 32);
		byte[] hmacTest = Arrays.copyOfRange(dataBytes, dataBytes.length - 32, dataBytes.length);
		
		// Verify HMAC
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(macKeySpec);
		mac.update(initVector);
		mac.update(vaultEntryEnc);
		byte[] hmac = mac.doFinal();

		int diff = hmac.length ^ hmacTest.length;
		for(int i = 0; i < hmac.length && i < hmacTest.length; i++) {
			diff |= hmac[i] ^ hmacTest[i];
		}
		if (diff != 0) {
			System.out.println("The hmac isn't correct!");
			System.exit(1);
		}
		
		// Decrypt
		AESCBCCipherWrapper cipher = new AESCBCCipherWrapper(srw, 256);
		byte[] vaultEntry = cipher.decrypt(vaultEntryEnc, initVector, encKeySpec);
		return vaultEntry;
	}
	
	public User loadUser(Gson gson) {
		// Load User from JSON 
		File myFile = new File(userFile);
		if (!myFile.exists()) {
			System.out.println("User is NOT registered. To register use the command reg");
			System.exit(1);
		}
		Scanner myReader;
		ByteArrayOutputStream out = null;
		String jsonString = "";
		try {
			myReader = new Scanner(myFile);
			out = new ByteArrayOutputStream();
			while (myReader.hasNextLine()) {
				out.write(Utils.toByteArray(myReader.nextLine()));
			}
			jsonString = out.toString();
		}
		catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
				
		User user = gson.fromJson(jsonString, User.class);
		return user;
	}
	
	public static void main(String[] args) throws Exception {
		PasswordManager pm = new PasswordManager();
		
		switch (args[0]) {
		case("reg"): {
			pm.register(Arrays.copyOfRange(args, 1, args.length));
			break;
		}
		case("add"): {
			pm.add(Arrays.copyOfRange(args, 1, args.length));
			break;
		}
		case("rm"):{
			pm.remove(Arrays.copyOfRange(args, 1, args.length));
			break;
		}
		case("get"): {
			pm.get(Arrays.copyOfRange(args, 1, args.length));
			break;
		}
		case("res"): {
			pm.reset(Arrays.copyOfRange(args, 1, args.length));
			break;
		}
		case("up"): {
			pm.update(Arrays.copyOfRange(args, 1, args.length));
			break;
		}
		default:
			break;
		}
	}
}
