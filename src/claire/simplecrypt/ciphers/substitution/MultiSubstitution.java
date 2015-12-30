package claire.simplecrypt.ciphers.substitution;

import claire.simplecrypt.standards.ICipher;

public class MultiSubstitution 
	   implements ICipher<MultiSubstitutionKey> {

	private char[][] key;
	private char[] alphabet;
	
	private int ekey = 0;
	private int dkey = 0;
	
	private MultiSubstitutionKey master;
	
	public MultiSubstitution(MultiSubstitutionKey key)
	{
		this.key = key.getKey();
		this.alphabet = key.getAlphabet();
		this.master = key;
	}
	
	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			final char[] key = this.key[ekey++];
			if(ekey == this.key.length)
				ekey = 0;
			final char c = plaintext[start];
			for(int i = 0; i < alphabet.length; i++)
				if(c == alphabet[i]) {
					plaintext[start] = key[i];
					break;
				}
			start++;
		}
	}

	public void encipher(char[] plaintext, int start0, char[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			final char[] key = this.key[ekey++];
			if(ekey == this.key.length)
				ekey = 0;
			final char c = plaintext[start0++];
			for(int i = 0; i < alphabet.length; i++)
				if(c == alphabet[i]) {
					ciphertext[start1] = key[i];
					break;
				}
			start1++;
		}
	}
	
	public void decipher(char[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			final char[] key = this.key[dkey++];
			if(dkey == this.key.length)
				dkey = 0;
			final char c = ciphertext[start];
			for(int i = 0; i < alphabet.length; i++)
				if(c == key[i]) {
					ciphertext[start] = alphabet[i];
					break;
				}
			start++;
		}
	}

	public void decipher(char[] ciphertext, int start0, char[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			final char[] key = this.key[dkey++];
			if(dkey == this.key.length)
				dkey = 0;
			final char c = ciphertext[start0++];
			for(int i = 0; i < alphabet.length; i++)
				if(c == key[i]) {
					plaintext[start1] = alphabet[i];
					break;
				}
			start1++;
		}
	}

	public void reset() 
	{
		this.ekey = 0;
		this.dkey = 0;
	}

	public void setKey(MultiSubstitutionKey key)
	{
		this.key = key.getKey();
		this.alphabet = key.getAlphabet();
		this.master = key;
		this.ekey = 0;
		this.dkey = 0;
	}

	public void destroy()
	{
		this.key = null;
		this.alphabet = null;
		this.key = null;
		this.ekey = 0;
		this.dkey = 0;
	}

	public MultiSubstitutionKey getKey()
	{
		return this.master;
	}

}
