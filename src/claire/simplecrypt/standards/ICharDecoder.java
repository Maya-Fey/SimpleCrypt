package claire.simplecrypt.standards;

public interface ICharDecoder {

	void decode(char[] codetext, int start, int len);
	void decode(char[] codetext, int start0, char[] plaintext, int start1, int len);
	
	IDecipherer<?, ?> getDecipherer();
	
	default void decode(char[] codetext)
	{
		decode(codetext, 0, codetext.length);
	}
	
	default char[] decode_copy(char[] codetext)
	{
		char[] plaintext = new char[getDecipherer().plaintextSize(codetext.length)];
		decode(codetext, 0, plaintext, 0, codetext.length);
		return plaintext;
	}

}
