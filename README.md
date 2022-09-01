# Security-Application
I built an application in JAVA where one party encrypts a file, digitally signs it and sends it to the second party, who decrypts the file and checks the digital signature.

encrypt.java :
• First, we will randomly generate a symmetric key, with this key we will encrypt the file.
• I used hybrid encryption, since the text is symmetric encrypted, and then the symmetric key is encrypted with asymmetric encryption.
• Now, with the symmetric key I will encrypt the text file.
• Next, I will want to encrypt the symmetric key, with asymmetric encryption. It will be encrypted using the receiving party's public key.
• After we have finished handling the confidentiality of the file, we will move on to handling its integrity, that is, we will perform a digital signature.
I chose to make an asymmetric digital signature. For this we will need the private key of party A.
•  I will hash the text before it was encrypted, and then will encrypt the hash value we received using the private key.

decrypt.java :
• In the first step, I will decrypt the symmetric key (which is encrypted with asymmetric encryption), and for this we need the public key of the sending party.
• Now, we will decrypt the text using the symmetric key.
• Finally, we must check the digital signature of the sender, using the public key of the signing party.
I will hash the encrypted text, decrypt the digital signature using the signer's public, and compare the two values.
• If the values are the same - we will save the decoded text in the file.
