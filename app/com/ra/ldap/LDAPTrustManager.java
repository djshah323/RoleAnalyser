package com.ra.ldap;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class LDAPTrustManager implements X509TrustManager {
    private X509TrustManager pkixTrustManager;

    public LDAPTrustManager() throws Exception {

        FileInputStream keyStoreIStream = null;
        try {
            // Open the stream to read in the keystore.
            keyStoreIStream = new FileInputStream("trustercerts"); //$NON-NLS-1$
        } catch (FileNotFoundException e) {
            // If the path does not exist then a null stream means
            // the keystore is initialized empty. If an untrusted
            // certificate chain is trusted by the user, then it will be
            // saved in the file pointed to by keyStorePath.
            keyStoreIStream = null;
        }

        // Create a KeyStore Object
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        // Init the Keystore with the contents of the keystore file.
        // If the input stream is null the keystore is initialized
        // empty.
        // keyStore.load(keyStoreIStream, keyStorePassword);

        // Close keystore input stream
        if (keyStoreIStream != null) {
            keyStoreIStream.close();
            keyStoreIStream = null;
        }

        keyStore.load(keyStoreIStream, "passphrase".toCharArray()); //$NON-NLS-1$

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX"); //$NON-NLS-1$
        tmf.init(keyStore);

        TrustManager tms[] = tmf.getTrustManagers();

        /*
         * Iterate over the returned trustmanagers, look for an instance of
         * X509TrustManager. If found, use that as our "default" trust manager.
         */
        for (int i = 0; i < tms.length; i++) {
            if (tms[i] instanceof X509TrustManager) {
                pkixTrustManager = (X509TrustManager) tms[i];
                return;
            }
        }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        try {
            pkixTrustManager.checkClientTrusted(chain, authType);
        } catch (CertificateException excep) {
            // do any special handling here, or rethrow exception.
        }

    }

    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        try {
            pkixTrustManager.checkServerTrusted(chain, authType);
        } catch (Exception excep) {
            /*
             * Possibly pop up a dialog box asking whether to trust the cert
             * chain.
             */

        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return pkixTrustManager.getAcceptedIssuers();
    }
}

