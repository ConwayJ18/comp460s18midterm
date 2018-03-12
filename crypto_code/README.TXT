Each src folder corresponds to a different level of security, as dictated by the guidelines.

For testing purposes, I've included "confidential.txt" as the file to be transmitted.

To run through the encryption/decryption process:

1) Generate public/private keys for Bob/Alice by running keypairs/GenerateKeys.java
1.a) This will put the public/private key pairs in the KeyPairs folder
1.b) This only needs to be done once

2) Generate a Symmetric Key by running symmetrickeys/GenerateSymmetricKey.java
2.a) This will put the key in the SymmetricKey folder
2.b) This also only needs to be done once

3) Perform Bob's actions (encryption) by running bob/StartEncryption.java
3.a) This generates files in the EncryptedFiles folder, which are the ones that would be sent

4) Perform Alice's actions (decryption) by running alice/StartDecryption.java
4.a) This generates files in the DecryptedFiles folder, which Alice can read
4.b) If the decryption fails due to corruption, the operation quits and an error message is printed
