package com.company;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;


public class Encrypt {
    public static void encrypt(String keystoreKeyPassword) throws KeyStoreException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException {
        // use base64 encoder
        Base64.Encoder base64Encoder = Base64.getEncoder();

        // generate symmetric key Randomly
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey symmetricKey = keyGenerator.generateKey();

        // generate random IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec IV = new IvParameterSpec(iv);

        // initialize cipher in ENCRYPT_MODE for symmetric encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, IV);

        // encrypt plaintext with symmetric key into new file
        FileWriter configFile = new FileWriter("config_file",false);
        FileInputStream inputStream = new FileInputStream("plaintext.txt");
        ByteArrayOutputStream bytes_output = new ByteArrayOutputStream();
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                bytes_output.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {

            bytes_output.write(outputBytes);
        }

        inputStream.close();

        byte[] encoded = base64Encoder.encode(bytes_output.toByteArray());
        bytes_output.close();

        configFile.write(new String(encoded)+"\n");
        //make a separate file just for the encrypted text
        FileWriter encrypted_file = new FileWriter("encrypted_file", false);
        encrypted_file.write(new String(encoded));
        encrypted_file.close();

        // encrypt the symmetric key with asymmetric encryption - RSA
        cipher = Cipher.getInstance("RSA");
        // get private key of userA
        KeyStore ks_userA = KeyStore.getInstance("PKCS12");
        InputStream readStream_userA = new FileInputStream("userA.keystore"); // file path to userA's keystore
        ks_userA.load(readStream_userA, keystoreKeyPassword.toCharArray());
        Key privateKeyA = ks_userA.getKey("userA", keystoreKeyPassword.toCharArray()); // This is the secret key!
        readStream_userA.close();
        // get public key of userB
        Certificate certB = ks_userA.getCertificate("userB");
        PublicKey publicKeyB = certB.getPublicKey(); // This is the public key!
        //encrypt the symmetric key
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyB);
        byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey.getEncoded());
        // save the symmetric key into hte config file
        configFile.write(new String(base64Encoder.encode(encryptedSymmetricKey))+"\n");

        // sign the plaintext with a digital signature
        // Hash the plaintext
        byte[] messageBytes = Files.readAllBytes(Paths.get("plaintext.txt"));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(messageBytes);

        // encrypt the hashed file
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKeyA);
        byte[] digitalSignature = cipher.doFinal(messageHash);

        // save the digital signature into a file
        configFile.write(new String(base64Encoder.encode(digitalSignature))+"\n");

        // save IV in config file
        configFile.write(new String(base64Encoder.encode(IV.getIV()))+"\n");

        configFile.close();
    }

    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, UnrecoverableKeyException, IllegalBlockSizeException, NoSuchPaddingException, CertificateException, KeyStoreException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        encrypt(args[0]);
    }
}