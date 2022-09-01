package com.company;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;


public class Decrypt {

    public static void decrypt(String passwordB) throws IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        String s = new String (Files.readAllBytes(Paths.get("config_file")));

        FileWriter decryptedFile = new FileWriter("decrypted.txt",false);

        Base64.Decoder base64Decoder = Base64.getDecoder();
        // get parameters from config file
        String[] params = s.split("\n");  //Split the word using space
        byte[] enc_text = base64Decoder.decode(params[0]);
        byte[] symKey_str = base64Decoder.decode(params[1]);
        byte[] signature = base64Decoder.decode(params[2]);
        byte[] iv = base64Decoder.decode(params[3]);

        //decrypt the symmetric key which is encrypted with RSA.
        //get the private key of userB
        KeyStore ks_userB = KeyStore.getInstance("PKCS12");
        InputStream readStream_userB = new FileInputStream("userB.keystore"); // file path to userA's keystore
        ks_userB.load(readStream_userB, passwordB.toCharArray());
        Key privateKeyB = ks_userB.getKey("userB", passwordB.toCharArray()); // This is the secret key!
        readStream_userB.close();
        //get the public key of userA
        Certificate certA = ks_userB.getCertificate("userA");
        Key publicKeyA = certA.getPublicKey();

        //use the privateKey of userB in order to decrypt the key
        IvParameterSpec IV = new IvParameterSpec(iv);
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, privateKeyB);
        byte[] de_symKey = rsa.doFinal(symKey_str);

        //decrypt the text
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(de_symKey,"AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, IV);
        byte[] dec_text = cipher.doFinal(enc_text);
        //decrypt hash message
        rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, publicKeyA);
        byte[] decryptedMessageHash = rsa.doFinal(signature);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] newMessageHash = md.digest(dec_text);

        //compare
        boolean isCorrect = Arrays.equals(decryptedMessageHash, newMessageHash);

        if (isCorrect)
        {
            decryptedFile.write(new String(dec_text));

        }
        else
        {
            decryptedFile.write("Error!");
        }
        decryptedFile.close();

    }
    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, UnrecoverableKeyException, IllegalBlockSizeException, NoSuchPaddingException, CertificateException, KeyStoreException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        decrypt(args[0]);

    }
}