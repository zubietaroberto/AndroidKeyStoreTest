package pa.com.poroto.pktest;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.TextView;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

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
    public TextView mTextPublicKey;

    @InjectView(R.id.text3)
    public TextView mTextPrivateKey;

    @InjectView(R.id.text4)
    public TextView mTextApk;

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
            final KeyPair key = KeyUtils.generateRSAKey();

            mTextPublicKey.setText(KeyUtils.byteArrayToHexString(key.getPublic().getEncoded()));
            mTextPrivateKey.setText(KeyUtils.byteArrayToHexString(key.getPrivate().getEncoded()));
            mTextApk.setText(KeyUtils.getCertificateSHA1Fingerprint(getActivity()));

        } catch (NoSuchAlgorithmException | CertificateException e) {

            //Should never happen
            e.printStackTrace();
        }

    }
}
