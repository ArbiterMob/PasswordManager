package org.arbitermob.core;

public class User {
	private String saltEmail;
	private String masterPasswordHash;
	private String protectedSymmetricKey;
	
	public User(String saltEmail, String masterPasswordHash, String protectedSymmetricKey) {
		super();
		this.saltEmail = saltEmail;
		this.masterPasswordHash = masterPasswordHash;
		this.protectedSymmetricKey = protectedSymmetricKey;
	}

	public String getSaltEmail() {
		return saltEmail;
	}

	public String getMasterPasswordHash() {
		return masterPasswordHash;
	}


	public String getProtectedSymmetricKey() {
		return protectedSymmetricKey;
	}
		
}
