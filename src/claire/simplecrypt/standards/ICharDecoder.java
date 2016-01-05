package claire.simplecrypt.standards;

public interface ICharDecoder {

	void decode(char[] plaintext, int start, int len);
	void decode(char[] plaintext, int start0, char[] codetext, int start1, int len);
	
	IDecipherer<?> getDecipherer();
	
	default void decode(char[] plaintext)
	{
		decode(plaintext, 0, plaintext.length);
	}
	
	default char[] decode_copy(char[] plaintext)
	{
		char[] codetext = new char[plaintext.length];
		decode(plaintext, 0, codetext, 0, plaintext.length);
		return codetext;
	}

}
