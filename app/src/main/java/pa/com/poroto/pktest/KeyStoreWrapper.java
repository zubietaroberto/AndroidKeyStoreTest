package pa.com.poroto.pktest;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

/**
 * Created by RobertoEduardo on 2014-09-17.
 */
public class KeyStoreWrapper {

    private static final String sAlgorithm = "RSA";
    private static final String sProvider = "AndroidOpenSSL";
    private static final String sKeyStore = "AndroidKeyStore";
    private static final String sAlgorithm_Decryption = "RSA/ECB/PKCS1Padding";

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static PublicKey generateRSA(final Context pContext, final String pAlias) {

        // Source Implementation:
        // http://developer.android.com/training/articles/keystore.html

        /*
        * Generate a new entry in the KeyStore by using the
        * KeyPairGenerator API. We have to specify the attributes for a
        * signed X.509 certificate here so the KeyStore can attach
        * the public key part to it. It can be replaced later with a
        * certificate signed by a Certificate Authority (CA) if needed.
        * */
        final Calendar cal = Calendar.getInstance();
        final Date now = cal.getTime();
        cal.add(Calendar.YEAR, 1);
        final Date end = cal.getTime();

        //Build Spec
        final KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(pContext)
                .setAlias(pAlias)
                .setStartDate(now)
                .setEndDate(end)
                .setSerialNumber(BigInteger.valueOf(1))
                .setSubject(
                        new X500Principal(String.format("CN=%s, OU=%s", pAlias,
                                pContext.getPackageName())))
                .build();

        try {

            //Generate
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(sAlgorithm, sKeyStore);
            kpg.initialize(spec);
            return kpg.generateKeyPair().getPublic();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {

            //TODO: Expand
            e.printStackTrace();
            throw new RuntimeException(e);
        }

    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static List<String> getStoredKeys() {
        try {

            final KeyStore ks = KeyStore.getInstance(sKeyStore);
            ks.load(null);
            return Collections.list(ks.aliases());

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {

            //TODO: Expand
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static byte[] decrypt(final byte[] pData, final String pAlias) {

        /*
        * Use a PrivateKey in the KeyStore to create a signature over
        * some data.
        */
        try {
            final KeyStore ks = KeyStore.getInstance(sKeyStore);
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(pAlias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new RuntimeException("Wrong Entry Type");
            }

            final Cipher cipher = Cipher.getInstance(sAlgorithm_Decryption, sProvider);
            cipher.init(Cipher.DECRYPT_MODE, ((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
            return cipher.doFinal(pData);

        } catch (KeyStoreException | CertificateException | InvalidKeyException |
                NoSuchAlgorithmException | IOException | NoSuchPaddingException |
                BadPaddingException | IllegalBlockSizeException |
                UnrecoverableEntryException | NoSuchProviderException e) {

            //TODO: Expand
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static byte[] encrypt(final byte[] pInput, final String pAlias) {

        try {

            KeyStore instance = KeyStore.getInstance(sKeyStore);
            instance.load(null);
            final PublicKey pk = instance.getCertificate(pAlias).getPublicKey();

            final Cipher cipher = Cipher.getInstance(sAlgorithm_Decryption, sProvider);
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            return cipher.doFinal(pInput);

        } catch (KeyStoreException | CertificateException | InvalidKeyException |
                NoSuchAlgorithmException | IOException | NoSuchPaddingException |
                BadPaddingException | IllegalBlockSizeException | NoSuchProviderException e) {

            //TODO: Expand
            e.printStackTrace();
            throw new RuntimeException(e);
        }

    }


}
