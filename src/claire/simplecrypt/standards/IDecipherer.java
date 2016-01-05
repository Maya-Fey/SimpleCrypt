package claire.simplecrypt.standards;

public interface IDecipherer<Key extends ISecret<Key>>
	   extends ICipherer<Key> {
	
	void decipher(byte[] ciphertext, int start, int len);
	void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len);
	int plaintextSize(int cipher);
	
	default void decipher(byte[] ciphertext)
	{
		decipher(ciphertext, 0, ciphertext.length);
	}
	
	default byte[] decipher_copy(byte[] ciphertext)
	{
		byte[] plaintext = new byte[ciphertext.length];
		decipher(ciphertext, 0, plaintext, 0, ciphertext.length);
		return plaintext;
	}

}
