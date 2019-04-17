package net.kberstene.certchecker;

import android.content.Context;
import android.os.Bundle;
import android.os.StrictMode;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {
    private final String TAG = MainActivity.class.getSimpleName();
    private EditText urlEditText;
    private Button testButton;
    private Context context;
    CompositeTrustManager trustManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        context = this;

        // Need to allow strict mode because we're doing everything from MainActivity
        // Normally we shouldn't do this, but this is a small app for testing so who cares
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        urlEditText = (EditText)findViewById(R.id.urlEditText);
        trustManager =  new CompositeTrustManager(context);

        testButton = (Button)findViewById(R.id.testButton);
        testButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                URL url;
                HttpsURLConnection urlConnection;
                InputStream in;

                try {
                    url = new URL(urlEditText.getText().toString());
                    urlConnection = (HttpsURLConnection)url.openConnection();
                    urlConnection.setSSLSocketFactory(trustManager.getSocketFactory());
                    in = urlConnection.getInputStream();
                } catch (MalformedURLException mue) {
                    Toast.makeText(context, "Malformed URL Exception", Toast.LENGTH_SHORT).show();
                    Log.w(TAG, Log.getStackTraceString(mue));
                    return;
                } catch (SSLHandshakeException she) {
                    // Cert not trusted
                    Toast.makeText(context, "Certificate not trusted", Toast.LENGTH_SHORT).show();
                    Log.w(TAG, Log.getStackTraceString(she));
                    return;
                } catch (SSLPeerUnverifiedException spue) {
                    Toast.makeText(context, "Hostname not verified", Toast.LENGTH_SHORT).show();
                    Log.w(TAG, Log.getStackTraceString(spue));
                    return;
                } catch (IOException ioe) {
                    Toast.makeText(context, "IOException", Toast.LENGTH_SHORT).show();
                    Log.w(TAG, Log.getStackTraceString(ioe));
                    ioe.printStackTrace();
                    return;
                }

                Toast.makeText(context, "Test successful", Toast.LENGTH_SHORT).show();
            }
        });
    }
}
