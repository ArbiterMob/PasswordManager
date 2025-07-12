## PasswordManager
This simple CLI application allows the user to securely store, retrieve, and manage credentials locally. It mimics [Bitwarden](https://bitwarden.com/)'s model by using a master password to derive cryptographic keys, which then protect the Vault entries.

---

## Security Architecure
Below is a high-level view of the key steps taken to protect the data.

### Registration (Key Derivation and Encryption)
1. **Master Key Derivation**
    * Uses PBKDF2 with HMAC-SHA256, 600,000 iterations
    * Payload: master password, Salt: user's email address
    * Output: 256-bit **Master Key**
2. **Master Key Stretching**
    * HKDF with HMAC-SHA256 to expand the **Master Key** to 512 bits
    * Output: 512-bit **Stretched Master Key**
3. **Symmetric Key**
    * Generate a random 512-bit **Symmetric Key** and a 128-bit IV via CSPRNG
    * Encrypt the **Symmetric Key** with AES-256-CBC using the **Stretched Master Key** and IV
    * Store the result as **Protected Symmetric Key**
4. **Master Password Hash**
    * Re-run PBKDF2 on the **Master Key** with the master password as salt
    * Store the result for authentication (the actual master password is never saved)

---

### Autentication and Decryption
1. **Master Key Re-Derivation**
    * User enters master password
    * Derive the same **Master Key** using PBKDF2 with the email as salt
2. **Verify Password**
    * Recompute the **Master Password Hash** and compare it with the stored hash
3. **Key Unwrapping**
    * Stretch the **Master Key** via HKDF to obtain the **Stretched Master Key** as mentioned before
    * Decrypt the **Protected Symmetric Key** with AES-256-CBC and obtain the **Symmetric Key**
4. **Vault Access**
    * Use the **Symmetric Key** to decrypt or encrypt Vault entries
  
---

## Encryption Protocols
* **AES-256-CBC** for symmetric encryption
* **HMAC-SHA256** for messagge autentication
This combined scheme (AES256-CBC-HMAC-SHA256) protects confidentiality, integrity and authentication, and would support future cloud storage securely

---

## Getting Started

### Prerequisites
* Java 11+
* Apache Maven

### Build
```bash
$ mvn clean package
```

The executable JAR will be generated in `target/` (e.g. `pwdmng-1.0.0-beta.jar`)

### Usage
```bash
$ java -jar target/pwdmng-1.0.0-beta-jar <command>
```

---

## Commands

| Command | Description                 |
| ---     | ---                         |
| `reg`   | Register a new User         |
| `add`   | Add a new Vault entry       |
| `get`   | Retrieve an existing entry  |
| `rm`    | Remove a Vault entry        |
| `up`    | Update a Vault entry        |
