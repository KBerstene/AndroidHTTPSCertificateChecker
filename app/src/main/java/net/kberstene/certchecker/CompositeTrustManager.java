package net.kberstene.certchecker;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.support.v7.app.AlertDialog;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

@TargetApi(18)
public class CompositeTrustManager implements X509TrustManager {
    private final String TAG = CompositeTrustManager.class.getSimpleName();
    private final String CERT_PREF_STRING = "TRUSTED_CERTIFICATES";
    private TrustManager[] trustManagers;
    private Context context;
    private KeyStore keyStore;
    private SharedPreferences prefs;

    public CompositeTrustManager(Context context) {
        this.context = context;
        this.prefs = context.getSharedPreferences("prefs", Context.MODE_PRIVATE);

        // TESTING - Reset saved certs
        //Log.w(TAG, "Resetting saved certificates for testing purposes only");
        //this.prefs.edit().remove(CERT_PREF_STRING).apply();

        this.initKeyStore();

        this.initTrustManagers();
    }

    private void initKeyStore() {
        // Initialize the keystore
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException kse) {
            Log.w(TAG, Log.getStackTraceString(kse));
            Toast.makeText(context, "Could not retrieve custom trusted certificates", Toast.LENGTH_SHORT).show();
            keyStore = null;
            return;
        }

        // Load saved certs
        String trustedCertsPref = prefs.getString(CERT_PREF_STRING, null);
        try {
            if (trustedCertsPref != null) {
                ByteArrayInputStream trustedCertsBytes = new ByteArrayInputStream(Base64.decode(trustedCertsPref.getBytes(), Base64.DEFAULT));
                keyStore.load(trustedCertsBytes, null);
                Log.w(TAG, "Imported trusted certificates");
            } else {
                Log.w(TAG, "No custom trusted certificates to load");
                keyStore.load(null);
            }
        } catch (EOFException eof) {
            // Expect an EOF at the end of the stream.  Everything is fine.
        } catch (IOException|CertificateException|NoSuchAlgorithmException e) {
            Log.w(TAG, "Could not import saved certs!");
            Toast.makeText(context, "Could not import saved certs!", Toast.LENGTH_SHORT).show();
            Log.w(TAG, Log.getStackTraceString(e));
        }
    }

    private void initTrustManagers() {
        try {
            // Get system TrustManager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore)null);
            this.trustManagers = trustManagerFactory.getTrustManagers();

            if (keyStore != null) {
                // Get custom TrustManager
                trustManagerFactory.init(this.keyStore);
                this.addTrustManagers(trustManagerFactory.getTrustManagers());
            }
        } catch (KeyStoreException kse) {
            Log.w(TAG, Log.getStackTraceString(kse));
        } catch (NoSuchAlgorithmException nsae) {
            Log.w(TAG, Log.getStackTraceString(nsae));
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException exception = new CertificateException("Unknown certificate exception - this should never throw");

        for (TrustManager trustManager : this.trustManagers) {
            try {
                ((X509TrustManager) trustManager).checkClientTrusted(chain, authType);
                // If any one of the trustManagers trust the cert, that's good enough
                return;
            } catch (CertificateException ce) {
                exception = ce;
            }
        }

        throw exception;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        CertificateException exception = new CertificateException("Unknown certificate exception - this should never throw");

        for (TrustManager trustManager : this.trustManagers) {
            try {
                ((X509TrustManager)trustManager).checkServerTrusted(chain, authType);
                // If any one of the trustManagers trust the cert, that's good enough
                return;
            } catch (CertificateException ce) {
                exception = ce;
            }
        }

        promptForCertificateTrust(chain[0]);
        throw exception;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> acceptedIssuers = new ArrayList<>();

        for (TrustManager trustManager : this.trustManagers) {
            Collections.addAll(acceptedIssuers, ((X509TrustManager)trustManager).getAcceptedIssuers());
        }

        return acceptedIssuers.toArray(new X509Certificate[0]);
    }

    public SSLSocketFactory getSocketFactory() {
        try {
            // Initialize SSLContext
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[] { this }, new java.security.SecureRandom());
            return sc.getSocketFactory();
        } catch (NoSuchAlgorithmException nsae) {
            Log.w(TAG, Log.getStackTraceString(nsae));
        } catch (KeyManagementException kme) {
            Log.w(TAG, Log.getStackTraceString(kme));
        }

        return null;
    }

    private void addTrustManagers(TrustManager[] trustManagers) {
        List<TrustManager> newTrustManagers = new ArrayList<>();

        Collections.addAll(newTrustManagers, this.trustManagers);
        Collections.addAll(newTrustManagers, trustManagers);

        this.trustManagers = newTrustManagers.toArray(new TrustManager[0]);
    }

    private void trustUnknownCertificate(X509Certificate cert) {
        if (keyStore != null) {
            try {
                // Trust certificate in the keystore
                keyStore.setCertificateEntry(new String(cert.getSignature()), cert);

                // Store the trusted certificate from the keystore into an array for storage
                ByteArrayOutputStream trustCertOutputStream = new ByteArrayOutputStream();
                keyStore.store(trustCertOutputStream, null);

                // Store the keyStore output in SharedPreferences
                // Stored certs must be encoded via Base64 or data will be lost
                prefs.edit().putString(CERT_PREF_STRING, Base64.encodeToString(trustCertOutputStream.toByteArray(), Base64.DEFAULT)).apply();
            } catch (Exception e) {
                Log.w(TAG, Log.getStackTraceString(e));
                Toast.makeText(context, "Encountered error; could not trust certificate", Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(context, "Trusting custom certificates currently unavailable", Toast.LENGTH_SHORT).show();
        }
    }

    private void promptForCertificateTrust(final X509Certificate cert) {
        Log.w(TAG, "Showing Alert");
        View alertLayout = View.inflate(context, R.layout.cert_alert, null);
        StringBuilder sanString = new StringBuilder();
        Collection<List<?>> altNames;
        final CompositeTrustManager compositeTrustManager = this;

        // Get SANs into string form
        try {
            altNames = cert.getSubjectAlternativeNames();
        } catch (CertificateParsingException cpe) {
            cpe.printStackTrace();
            return;
        }

        if (altNames != null) {
            for (List<?> altName : altNames) {
                Integer altNameType = (Integer) altName.get(0);
                if (altNameType != 2 && altNameType != 7) // dns or ip
                    continue;
                sanString.append((String)altName.get(1));
                sanString.append("\n");
            }
            // Remove last newline
            sanString.delete(sanString.length() - 1, sanString.length() - 1);
        }

        // Set text from cert info
        ((TextView) alertLayout.findViewById(R.id.textIssuer)).setText(cert.getIssuerDN().getName());
        ((TextView) alertLayout.findViewById(R.id.textSubject)).setText(cert.getSubjectDN().getName());
        ((TextView) alertLayout.findViewById(R.id.textSan)).setText(sanString.toString());

        AlertDialog.Builder builder = new AlertDialog.Builder(context, R.style.AlertDialog)
                .setTitle("Untrusted Certificate")
                .setPositiveButton("Trust", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        Log.w(TAG, "Attempting to add cert to trust");
                        compositeTrustManager.trustUnknownCertificate(cert);
                        compositeTrustManager.initTrustManagers();
                    }
                })
                .setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {

                    }
                })
                .setView(alertLayout);
        builder.create().show();
    }
}
