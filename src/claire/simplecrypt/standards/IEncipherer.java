package claire.simplecrypt.standards;

public interface IEncipherer<Key> 
	   extends ICipherer<Key> {
	
	void encipher(char[] plaintext, int start, int len);
	void encipher(char[] plaintext, int start0, char[] ciphertext, int start1, int len);
	
	default void encipher(char[] plaintext)
	{
		encipher(plaintext, 0, plaintext.length);
	}
	
	default char[] encipher_copy(char[] plaintext)
	{
		char[] ciphertext = new char[plaintext.length];
		encipher(plaintext, 0, ciphertext, 0, plaintext.length);
		return ciphertext;
	}

}
