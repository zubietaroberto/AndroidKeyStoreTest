package pa.com.poroto.pktest;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.security.KeyPairGeneratorSpec;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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
            throws CertificateException, NoSuchAlgorithmException {

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
        final MessageDigest md = MessageDigest.getInstance("SHA1");
        final byte[] publicKey = md.digest(c.getEncoded());
        return byteArrayToHexString(publicKey);
    }

    public static KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        final int keySize = 2048;

        final KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(keySize);

        return keyGenerator.generateKeyPair();
    }
}
