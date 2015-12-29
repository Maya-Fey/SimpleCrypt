package claire.simplecrypt.standards;

public interface IDecipherer<Key>
	   extends ICipherer<Key> {
	
	void decipher(char[] ciphertext, int start, int len);
	void decipher(char[] ciphertext, int start0, char[] plaintext, int start1, int len);
	
	default void decipher(char[] ciphertext)
	{
		decipher(ciphertext, 0, ciphertext.length);
	}
	
	default char[] decipher_copy(char[] ciphertext)
	{
		char[] plaintext = new char[ciphertext.length];
		decipher(ciphertext, 0, plaintext, 0, ciphertext.length);
		return plaintext;
	}

}
