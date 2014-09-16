package pa.com.poroto.pktest;

import android.app.Fragment;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import butterknife.ButterKnife;
import butterknife.InjectView;
import butterknife.OnClick;

/**
 * Created by RobertoEduardo on 2014-09-12.
 */
public class PrivateKeyFragment extends Fragment {

    @InjectView(R.id.editText1)
    public EditText mEditText;

    @InjectView(R.id.text1)
    public TextView mTextEncrypted;

    @InjectView(R.id.text2)
    public TextView mTextDecrypted;

    @InjectView(R.id.text3)
    public TextView mTextPublicKey;

    @InjectView(R.id.text4)
    public TextView mTextPrivateKey;

    @InjectView(R.id.text5)
    public TextView mTextApk;

    @InjectView(R.id.text_sha256)
    public TextView mTextHash;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        final View view = inflater.inflate(R.layout.fragment_privatekey, container, false);
        ButterKnife.inject(this, view);
        return view;
    }

    @Override
    public void onViewCreated(View view, Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        ButterKnife.reset(this);
    }

    /*
    Public Methods
     */
    @OnClick(R.id.button1)
    public void generateKey() {
        try {

            // Build the key
            final KeyPair key = KeyUtils.generateRSAKey();
            final byte[] publicKey = key.getPublic().getEncoded();
            final byte[] privateKey = key.getPrivate().getEncoded();

            // Display cryptographic data
            mTextPublicKey.setText(KeyUtils.byteArrayToHexString(publicKey));
            mTextPrivateKey.setText(KeyUtils.byteArrayToHexString(privateKey));
            mTextApk.setText(KeyUtils.getCertificateSHA1Fingerprint(getActivity()));

            //Public Key SHA-256
            final byte[] sha256 = KeyUtils.sha256(publicKey);
            mTextHash.setText(KeyUtils.byteArrayToHexString(sha256));

            final String text = mEditText.getText().toString();
            if (!TextUtils.isEmpty(text)){

                //Encode String
                final byte[] encData = KeyUtils.encryptRSA(text.getBytes(), key.getPublic());
                mTextEncrypted.setText(KeyUtils.byteArrayToHexString(encData));

                //Decode String
                final byte[] decData = KeyUtils.decryptRSA(encData, key.getPrivate());
                mTextDecrypted.setText(new String(decData));
            }

        } catch (CertificateException | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException e) {

            //Should never happen
            e.printStackTrace();
            throw new RuntimeException(e);
        }

    }
}
