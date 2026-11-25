package com.vrp.ks2probe;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.TextView;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class MainActivity extends Activity {
    private static final String TAG = "KS2_DDP_PROBE";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        String result = runProbe();
        tv.setText(result);
        setContentView(tv);
    }

    private String runProbe() {
        try {
            Log.i(TAG, "Starting Keystore2 Attestation Probe on SDK=" + Build.VERSION.SDK_INT + " MODEL=" + Build.MODEL);
            String alias = "ks2_ddp_probe_key";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge("ddp-ks2-probe".getBytes("UTF-8"));

            boolean strongBoxUsed = false;
            try {
                builder.setIsStrongBoxBacked(true);
                kpg.initialize(builder.build());
                kpg.generateKeyPair();
                strongBoxUsed = true;
            } catch (Exception sbEx) {
                Log.w(TAG, "StrongBox unavailable, falling back to TEE: " + sbEx.getMessage());
                builder.setIsStrongBoxBacked(false);
                kpg.initialize(builder.build());
                kpg.generateKeyPair();
            }

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain(alias);
            int totalBytes = 0;
            for (Certificate c : chain) {
                totalBytes += c.getEncoded().length;
            }
            byte[] leafDer = chain[0].getEncoded();
            boolean hasTag709 = containsBytes(leafDer, new byte[]{(byte) 0xBF, (byte) 0x85, (byte) 0x45});

            String summary = "PROBE_SUCCESS: strongBox=" + strongBoxUsed + ", chainLen=" + chain.length + ", totalDerBytes=" + totalBytes + ", hasTag709=" + hasTag709;
            Log.i(TAG, summary);
            return summary;
        } catch (Throwable t) {
            Log.e(TAG, "PROBE_FAILED", t);
            return "PROBE_FAILED: " + t.toString();
        }
    }

    private static boolean containsBytes(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
}
