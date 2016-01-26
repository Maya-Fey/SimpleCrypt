package claire.simplecrypt.standards;

public interface IEncipherer<Key extends ISecret<?>, State extends IState<?>> 
	   extends ICipherer<Key, State> {
	
	void encipher(byte[] plaintext, int start, int len);
	void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len);
	int ciphertextSize(int plain);
	
	default void encipher(byte[] plaintext)
	{
		encipher(plaintext, 0, plaintext.length);
	}
	
	default byte[] encipher_copy(byte[] plaintext)
	{
		byte[] ciphertext = new byte[plaintext.length];
		encipher(plaintext, 0, ciphertext, 0, plaintext.length);
		return ciphertext;
	}

}
