package org.arbitermob.core;

public class VaultEntry {
	private String nameService;
	private String protectedVaultEntry;
	
	public VaultEntry(String nameService, String protectedVaultEntry) {
		super();
		this.nameService = nameService;
		this.protectedVaultEntry = protectedVaultEntry;
	}

	public String getNameService() {
		return nameService;
	}

	public String getProtectedVaultEntry() {
		return protectedVaultEntry;
	}
	
	public void setProtectedVaultEntry(String protectedVaultEntry) {
		this.protectedVaultEntry = protectedVaultEntry;
	}
}
