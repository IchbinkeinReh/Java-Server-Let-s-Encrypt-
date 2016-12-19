import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import sun.misc.BASE64Decoder;

class HTTPSserver extends X509ExtendedKeyManager  {
    private X509ExtendedKeyManager km;

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
	return km.chooseClientAlias(keyType, issuers, socket);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
	return km.chooseServerAlias(keyType, issuers, socket);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
	return km.getCertificateChain(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
	return km.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
	return km.getPrivateKey(alias);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
	return km.getServerAliases(keyType, issuers);
    }
    
    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
	return km.chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
	return km.chooseEngineServerAlias(keyType, issuers, engine);
    }
    
    public HTTPSserver(int HTTPSportNumber, String pathToCert, HttpHandler httpHandler) {

	Runnable reloadCert = new Runnable() {
	    @Override
	    public void run() {
		try {
		    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		    keystore.load(null, null);

		    CertificateFactory cf = CertificateFactory.getInstance("X.509");
		    Certificate cer = (X509Certificate) cf.generateCertificate(new FileInputStream(pathToCert + "/fullchain.pem"));

		    String temp = new String(Files.readAllBytes(Paths.get(pathToCert + "privkey.pem")));
		    String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
		    privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
		    BASE64Decoder b64 = new BASE64Decoder();
		    byte[] decoded = b64.decodeBuffer(privKeyPEM);
		    PKCS8EncodedKeySpec key = new PKCS8EncodedKeySpec(decoded);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    PrivateKey pk = kf.generatePrivate(key);

		    keystore.setKeyEntry("cert", pk, "dummy".toCharArray(), new Certificate[] { cer });
		    
		    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		    kmf.init(keystore, "dummy".toCharArray());
		    HTTPSserver.this.km = (X509ExtendedKeyManager) kmf.getKeyManagers()[0];
		} catch (Exception e) {
		    e.printStackTrace();
		}
	    }
	};
	ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
	scheduler.scheduleAtFixedRate(reloadCert, 24 * 60 * 60, 24 * 60 * 60, TimeUnit.SECONDS);

	try {
	    reloadCert.run();
	    SSLContext sslContext = SSLContext.getInstance("TLS");
	    sslContext.init(new KeyManager[] { this }, null, new SecureRandom());
	    SSLContext.setDefault(sslContext);
	    
	    HttpsServer server = HttpsServer.create(new InetSocketAddress(HTTPSportNumber), 0);
	    server.createContext("/", httpHandler);
	    server.setExecutor(Executors.newCachedThreadPool());
	    server.setHttpsConfigurator(new HttpsConfigurator(SSLContext.getDefault()));
	    server.start();
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }

    public static void main(String[] arg) {
	new HTTPSserver(443, "/etc/letsencrypt/live/YOUR_CN", new HttpHandler() {

	    @Override
	    public void handle(HttpExchange t) throws IOException {
		String response = "This is an example response";
		t.sendResponseHeaders(200, response.length());
		OutputStream os = t.getResponseBody();
		os.write(response.getBytes());
		os.close();
	    }

	});
    }

}