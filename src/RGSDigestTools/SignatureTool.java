/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RGSDigestTools;

import RGSCommonUtils.TrustStoreLoader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author p.chavdarov
 */
public class SignatureTool {
    
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    public static byte[] HexToBytes(String signature) {
        char[] arr = signature.toCharArray();
            byte[] b_arr = new byte[arr.length/2];
            byte b = 0;
            int j = 0;
            for(int i = 0; i+2<=arr.length;i+=2 ){
                b = (byte) Integer.parseInt(String.format("%s%s",arr[i],arr[i+1]), 16);
                b_arr[j++] = (byte) (b);
            }
        return b_arr;
    }
    
    private final String signAlg;
    private String Provider;
    private PrivateKey signKey; 
    private PublicKey verifyKey;

    public SignatureTool(String signAlg, String CryptoProvider) {
        this.signAlg = signAlg;
        this.Provider = CryptoProvider;
    }
    
    public SignatureTool(String signAlg) {
        this.signAlg = signAlg;
    }

    
    public String sign(String dataToSign) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        Signature signer = Signature.getInstance(signAlg);
        signer.initSign(signKey);
        signer.update(dataToSign.getBytes());
        return bytesToHex(signer.sign());//Base64.encodeBase64String(signer.sign());//bytesToHex(signer.sign());
               
    }

    public boolean verify(String dataToVerify, byte[] signature) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
        Signature signer = Signature.getInstance(signAlg);
        signer.initVerify(verifyKey);
        signer.update(dataToVerify.getBytes());
        return signer.verify(signature);
        
    }
    
    /**
     * Init keys with private and public key from keystore
     * @param pKeyStorePath
     * @param pKeyStorePasswd
     * @param pDSAlias
     * @param pPrivKeyPasswd
     * @param pCheckDSAlias
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableEntryException 
     */
    public void initKeysWithKeystore(String pKeyStorePath, String pKeyStorePasswd, String pDSAlias, String pPrivKeyPasswd,  String pCheckDSAlias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException{
        KeyStore ks = TrustStoreLoader.loadKeyStore(pKeyStorePath,pKeyStorePasswd);
        KeyStore.PasswordProtection passProtection = new KeyStore.PasswordProtection(pPrivKeyPasswd.toCharArray());
        KeyStore.PrivateKeyEntry DSKeyEnt = (KeyStore.PrivateKeyEntry)ks.getEntry(pDSAlias, passProtection);
        KeyStore.PrivateKeyEntry CheckDSKeyEnt = (KeyStore.PrivateKeyEntry)ks.getEntry(pCheckDSAlias, passProtection);
        
        this.signKey = DSKeyEnt.getPrivateKey();
        this.verifyKey =  CheckDSKeyEnt.getCertificate().getPublicKey();
        
    }
    
    /**
     * Init keys with private key from keystore and pubkey from resource
     * @param pKeyStorePath
     * @param pKeyStorePasswd
     * @param pDSAlias
     * @param pPrivKeyPasswd
     * @param PubkeyResource 
     * @throws java.security.KeyStoreException 
     * @throws java.security.cert.CertificateException 
     * @throws java.security.NoSuchAlgorithmException 
     * @throws java.io.IOException 
     * @throws java.security.UnrecoverableEntryException 
     * @throws java.security.spec.InvalidKeySpecException 
     */
    public void initKeysWithAndFile(String pKeyStorePath, String pKeyStorePasswd, String pDSAlias, String pPrivKeyPasswd,  String PubkeyResource)
                throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, InvalidKeySpecException{
        KeyStore ks = TrustStoreLoader.loadKeyStore(pKeyStorePath,pKeyStorePasswd);
        KeyStore.PasswordProtection passProtection = new KeyStore.PasswordProtection(pPrivKeyPasswd.toCharArray());
        KeyStore.PrivateKeyEntry DSKeyEnt = (KeyStore.PrivateKeyEntry)ks.getEntry(pDSAlias, passProtection);
        
        this.signKey = DSKeyEnt.getPrivateKey();
        
        InputStream is = SignatureTool.class.getResourceAsStream(PubkeyResource);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int read = is.read();
        while(read != -1){
            baos.write(read);
            read = is.read();
        }
        
        byte[] keyBytes = baos.toByteArray();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.verifyKey = keyFactory.generatePublic(spec);
    }
    
    public String showKeys(){
        return String.format("Priv key :%s\nPubl key :%s", Base64.encodeBase64String(signKey.getEncoded()), Base64.encodeBase64String(verifyKey.getEncoded()));
    }
    
    
    
    
    
}
