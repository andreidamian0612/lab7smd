package com.andamian.laborator7;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.app.Dialog;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {
    private KeyStore.PrivateKeyEntry privateKeyEntry;
    private SharedPreferences sharedPreferences;
    private Cipher cipher;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        sharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);


        final EditText passwordInput = findViewById(R.id.pass);
        final EditText descriptionInput = findViewById(R.id.desc);
        Button saveButton = findViewById(R.id.save_button);
        Button showButton = findViewById(R.id.show);

        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            e.printStackTrace();
        }

        KeyguardManager keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        assert keyguardManager != null; //used to get rid of the warning
        if (!keyguardManager.isDeviceSecure()) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setMessage("you need lockscreen protection. do you want to create one?")
                    .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            startActivity(new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD));
                        }
                    })
                    .setNegativeButton("No", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            finish();
                        }
                    });

            Dialog dialog = builder.create();
            dialog.show();
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null, null);

            if (keyStore.containsAlias("alias_rsa_keys")) {
                Toast.makeText(this, "Key Already Generated", Toast.LENGTH_SHORT).show();
                privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("alias_rsa_keys", null);
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder("alias_rsa_keys",
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(2048)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .build();

                generator.initialize(keyGenParameterSpec);

                generator.generateKeyPair();
            }


        } catch (Exception e) {
            e.printStackTrace();
        }

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                String input = passwordInput.getText().toString();
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

                    byte[] cipher_res;

                    cipher_res = cipher.doFinal(input.getBytes());


                    String encodedData = Base64.encodeToString(cipher_res, Base64.DEFAULT);

                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    editor.putString("enc_pass", encodedData);
                    editor.putString("desc", descriptionInput.getText().toString());
                    editor.apply();
                } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
                    e.printStackTrace();
                }


            }
        });

        showButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }
                String encodedData = sharedPreferences.getString("enc_pass", "no_pass");
                if (encodedData.equals("no_pass")) {
                    try {
                        throw new Exception();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                byte[] encryptedData = Base64.decode(encodedData, Base64.DEFAULT);
                String data = null;
                try {
                    data = new String(cipher.doFinal(encryptedData));
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
                passwordInput.setText(data);
                descriptionInput.setText(sharedPreferences.getString("desc", "no_pass"));
            }
        });


    }
}
