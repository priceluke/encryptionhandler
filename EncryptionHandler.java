package org.lp00579.www;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * The Class EncryptionHandler.
 */
public class EncryptionHandler {

	/** The my private key. */
	private BigInteger myPrivateKey;

	/** The my public key. */
	private BigInteger[] myPublicKey;

	/** The connected public key. */
	private BigInteger[] connectedPublicKey;

	/**
	 * Instantiates a new encryption handler.
	 */
	public EncryptionHandler() {
		super();
		// Constructor creates user's private key on instantiation
		genPublic();
	}

	/**
	 * EncryptionHandler Gets the user's private key.
	 *
	 * @return the private key
	 */
	private BigInteger getMyPrivateKey() {
		return myPrivateKey;
	}

	/**
	 * Gets the client's public key.
	 *
	 * @return the connected public key
	 */
	private BigInteger[] getConnectedPublicKey() throws NullPointerException {
		if (connectedPublicKey[0] == null || connectedPublicKey[1] == null) {
			throw new NullPointerException("Connected Public Key Has Not Yet Been Set.");
		}
		return connectedPublicKey;
	}

	/**
	 * Gets the users public key.
	 *
	 * @return the public key
	 */
	public BigInteger[] getMyPublicKey() {
		return myPublicKey;
	}

	/**
	 * Sets the connected public key.
	 *
	 * @param connectedPublicKey
	 *            the new connected public key
	 */
	public void setConnectedPublicKey(BigInteger[] connectedPublicKey) {
		this.connectedPublicKey = connectedPublicKey;
	}

	/**
	 * Gen public.
	 */
	private void genPublic() {
		BigInteger p = genPrime();
		BigInteger q = genPrime();
		BigInteger n = p.multiply(q);
		BigInteger one = BigInteger.valueOf(1);
		BigInteger phi = p.subtract(one).multiply(q.subtract(one));
		BigInteger e;

		Random rand = new SecureRandom();

		do {
			e = new BigInteger(phi.bitLength(), rand);
		} while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));
		BigInteger d = e.modInverse(phi);

		this.myPublicKey = new BigInteger[] { n, e };
		genPrivate(phi, e);
	}

	/**
	 * Gen private.
	 *
	 * @param phi
	 *            phi
	 * @param e
	 *            exponent
	 */
	private void genPrivate(BigInteger phi, BigInteger e) {
		BigInteger d = e.modInverse(phi);
		this.myPrivateKey = d;
	}

	/**
	 * Gen prime.
	 *
	 * @return the generated prime number
	 */
	private BigInteger genPrime() {
		return BigInteger.probablePrime(2048, new Random());
	}

	/**
	 * Encrypt.
	 *
	 * @param clear
	 *            the clear text
	 * @return the encrypted string
	 */
	public String encrypt(String clear) {
		StringBuilder char_ascii = new StringBuilder();
		int length_lim = clear.length();
		if (clear.length() > 205) {
			length_lim = 205;
		}
		for (int i = 0; i < length_lim; i++) {
			char c = clear.charAt(i);
			char_ascii.append(String.format("%03d", Integer.parseInt(Integer.toString((int) c))));
		}
		BigInteger clear_ascii = new BigInteger(char_ascii.toString());
		BigInteger cipher_ascii = clear_ascii.modPow(this.connectedPublicKey[1], this.connectedPublicKey[0]);

		return cipher_ascii.toString();
	}

	/**
	 * Decrypt.
	 *
	 * @param cipher
	 *            the ciphered text
	 * @return the decrypted string
	 */
	public String decrypt(String cipher) {
		BigInteger cipher_big = new BigInteger(cipher);
		BigInteger decrypted_big_ascii = cipher_big.modPow(myPrivateKey, this.myPublicKey[0]);
		String decrypted_ascii = decrypted_big_ascii.toString();
		if (decrypted_ascii.length() % 3 != 0) {
			decrypted_ascii = "0" + decrypted_ascii;
		}
		String[] letters = decrypted_ascii.split("(?<=\\G...)");
		StringBuilder ret_str = new StringBuilder();
		for (String str : letters) {
			char c = (char) (Integer.parseInt(str));
			ret_str.append(c);
		}

		return ret_str.toString();
	}

	/**
	 * Crop.
	 *
	 * @param bigInteger
	 *            the initial big integer
	 * @return the cropped big integer (string)
	 */
	private String crop(BigInteger bigInteger_int) {
		String bigInteger = bigInteger_int.toString();
		if (bigInteger.length() > 50) {
			return bigInteger.substring(0, 50) + "...";
		} else {
			return bigInteger;
		}
	}

	/**
	 * Displays RSA information
	 *
	 * @return the information about current session
	 */
	public String display() {
		StringBuilder rsa = new StringBuilder("RSA Details:\n\n");
		rsa.append("Your Public Key: \n" + crop(getMyPublicKey()[0]) + crop(getMyPublicKey()[1]) + "\n\n");
		rsa.append(
				"Client Public Key: \n" + crop(getConnectedPublicKey()[0]) + crop(getConnectedPublicKey()[1]) + "\n\n");
		rsa.append("Your Private Key: \n" + crop(getMyPrivateKey()) + "\n\n");

		return rsa.toString().replaceAll("(.{100})", "$1\n");
	}

}
