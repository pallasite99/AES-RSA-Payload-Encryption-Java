# AES-RSA-payload-encryption-java
* A Plain Java implementation with Maven and Java for Payload Encryption - using AES for data encryption and RSA for AES key encryption.

### **Flow - Encryption**
1. Read data to be sent from a file.
2. Generate RSA key pair using BouncyCastle which will store public and private keys in separate files
3. Check if you can retrieve information from the respective keys because these will be further used for AES key encryption.
4. Encrypt the data to be sent using generated AES key and store it in a file
5. Encrypt the AES key using private RSA key and store it in a file to be used later for decryption.

### **Flow - Decryption**
1. Read encrypted AES key from a file.
2. Decrypt the AES Key with public RSA key
3. Decrypt data using the decrypted AES key.
4. This will give us the original data.

`Note:` Any tampering with the RSA/AES key data during data transmission will result in an error on the server side. This ensures that the data sent is secure.
