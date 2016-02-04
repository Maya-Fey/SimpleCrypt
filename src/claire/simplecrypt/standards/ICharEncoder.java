package claire.simplecrypt.standards;

public interface ICharEncoder {

	void encode(char[] plaintext, int start, int len);
	void encode(char[] plaintext, int start0, char[] codetext, int start1, int len);
	
	IEncipherer<?, ?> getEncipherer();
	
	default void encode(char[] plaintext)
	{
		encode(plaintext, 0, plaintext.length);
	}
	
	default char[] encode_copy(char[] plaintext)
	{
		char[] codetext = new char[getEncipherer().ciphertextSize(plaintext.length)];
		encode(plaintext, 0, codetext, 0, plaintext.length);
		return codetext;
	}
	
	int ciphertextSize(char[] text, int start, int len);
	
	default int ciphertextSize(char[] text)
	{
		return ciphertextSize(text, 0, text.length);
	}

}
