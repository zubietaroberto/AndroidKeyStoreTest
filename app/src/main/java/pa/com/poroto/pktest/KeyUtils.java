package pa.com.poroto.pktest;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by RobertoEduardo on 2014-09-12.
 */
public class KeyUtils {

    final protected static char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public static String byteArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;

        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
    }

    /*
    Source: http://stackoverflow.com/a/22506133/742188
     */
    public static String getCertificateSHA1Fingerprint(Context pContext)
            throws CertificateException{

        //Get the Package Manager
        final PackageManager pm = pContext.getPackageManager();
        final String packageName = pContext.getPackageName();
        final int flags = PackageManager.GET_SIGNATURES;

        //Get the package Signatures
        final PackageInfo packageInfo;
        try {
            packageInfo = pm.getPackageInfo(packageName, flags);
        } catch (PackageManager.NameNotFoundException e) {

            // This should never happen
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        final Signature[] signatures = packageInfo.signatures;
        final byte[] cert = signatures[0].toByteArray();

        //Build certificate from signature
        final InputStream input = new ByteArrayInputStream(cert);
        final CertificateFactory cf = CertificateFactory.getInstance("X509");
        final X509Certificate c = (X509Certificate) cf.generateCertificate(input);

        //Get the certificate's SHA1 signature
        try {

            final MessageDigest md = MessageDigest.getInstance("SHA1");
            final byte[] publicKey = md.digest(c.getEncoded());
            return byteArrayToHexString(publicKey);
        } catch (NoSuchAlgorithmException e) {

            //Should never happen. Fast Fail
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateRSAKey() {
        final int keySize = 2048;
        try {

            final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator.initialize(keySize);

            return keyGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {

            //Should never happen. Fast Fail
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static byte[] encryptRSA(final byte[] pInput, final PublicKey pKey)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        try {

            final Cipher encCipher = Cipher.getInstance("RSA");
            encCipher.init(Cipher.ENCRYPT_MODE, pKey);
            return encCipher.doFinal(pInput);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {

            //Should never happen. Fast Fail.
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static byte[] decryptRSA(final byte[] pInput, final PrivateKey pKey)
            throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        try {

            final Cipher decCipher = Cipher.getInstance("RSA");
            decCipher.init(Cipher.DECRYPT_MODE, pKey);
            return decCipher.doFinal(pInput);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {

            //Should never happen. Fast Fail.
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static byte[] sha256(final byte[] pInput){

        try {

            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            return digest.digest(pInput);

        } catch (NoSuchAlgorithmException e) {

            //Should never happen. Fast Fail
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
