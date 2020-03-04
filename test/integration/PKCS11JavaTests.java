import java.io.ByteArrayInputStream;
import java.io.InputStream;
/* Introspection to support Java < 9 */
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class PKCS11JavaTests {

	static final String PIN = "myuserpin";
	static final String KEY_ALIAS = "rsa1";

	static KeyStore KEY_STORE;
	static Provider PROV;

	@BeforeClass
	public static void beforeAllTestMethods() throws Exception {
		/*
		 * Generate a new provider to use the SUNPKCS11 module
		 *
		 */
		String cwd = System.getProperty("user.dir");
		Path libPath = Paths.get(cwd, "src/.libs/libtpm2_pkcs11.so.0.0.0");

		try {
			/* Java >= 9 */
			Method configure = Provider.class.getMethod("configure", String.class);
			String pkcs11Config = "--name = TPM2\nlibrary = " + libPath;
			PROV = Security.getProvider("SunPKCS11");
			PROV = (Provider) configure.invoke(PROV, pkcs11Config);
		} catch (NoSuchMethodException e) {
			/* Java <= 8 */
			Constructor SunPKCS11 = Class.forName("sun.security.pkcs11.SunPKCS11").getConstructor(InputStream.class);
			String pkcs11Config = "name = TPM2\nlibrary = " + libPath;
			ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11Config.getBytes());
			PROV = (Provider) SunPKCS11.newInstance(confStream);
		}

		/* add the provider */
		Security.addProvider(PROV);

		/* Generate a keystore from the provider */
		KEY_STORE = KeyStore.getInstance("PKCS11-TPM2");
		KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(PIN.toCharArray());
		KEY_STORE.load(null, pp.getPassword());
	}

	@Test
	public void test_rsa_crypto() throws Exception {

		/* Get the key/cert pair */
		Key rsaKey = KEY_STORE.getKey(KEY_ALIAS, null);
		Assert.assertEquals("RSA", rsaKey.getAlgorithm());

		X509Certificate certificate = (X509Certificate) KEY_STORE.getCertificate(KEY_ALIAS);

		/* get the public key from the cert */
		Key rsaPublicKey = certificate.getPublicKey();

		/* Encrypt public decrypt private */
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", PROV);

		String plaintext = "mysecretdata";

		byte[] plainData = plaintext.getBytes("UTF-8");

		cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
		byte[] encryptedData = cipher.doFinal(plainData);

		cipher.init(Cipher.DECRYPT_MODE, rsaKey);
		int output = cipher.getOutputSize(encryptedData.length);
		byte[] decryptedData = cipher.doFinal(encryptedData);

		String decrypted = new String(decryptedData, output - plainData.length, plainData.length);

		Assert.assertEquals(plaintext, decrypted);

		/* Encrypt private decrypt public */
		cipher.init(Cipher.ENCRYPT_MODE, rsaKey);
		encryptedData = cipher.doFinal(plainData);

		cipher.init(Cipher.DECRYPT_MODE, rsaPublicKey);
		output = cipher.getOutputSize(encryptedData.length);
		decryptedData = cipher.doFinal(encryptedData);

		Assert.assertArrayEquals(plainData, decryptedData);

		String s = new String(decryptedData);
		Assert.assertEquals(plaintext, s);
	}

	@Test
	public void test_signverify_signature() throws Exception {

		/* Get the key/cert pair */
		Key rsaKey = KEY_STORE.getKey(KEY_ALIAS, null);
		Assert.assertEquals("RSA", rsaKey.getAlgorithm());

		X509Certificate certificate = (X509Certificate) KEY_STORE.getCertificate(KEY_ALIAS);

		/* get the public key from the cert */
		Key rsaPublicKey = certificate.getPublicKey();

		/* Sign private Verify public */
		Signature signature = Signature.getInstance("SHA256withRSA", PROV);

		String plaintext = "mysecretdata";

		byte[] plainData = plaintext.getBytes("UTF-8");

		signature.initSign((PrivateKey) rsaKey);
		signature.update(plainData);
		byte[] signedData = signature.sign();

		signature.initVerify((PublicKey) rsaPublicKey);
		signature.update(plainData);

		boolean retSignature = signature.verify(signedData);
		Assert.assertTrue(retSignature);
	}

	public static void main(String[] args) {
		int rc = 1;
		Result result = JUnitCore.runClasses(PKCS11JavaTests.class);
		if (result.wasSuccessful()) {
			rc = 0;
			System.out.println("Success");
		} else {
			System.out.println("Failed");
		}

		for (Failure failure : result.getFailures()) {
			System.out.println(failure.toString());
		}

		System.exit(rc);
	}
}
