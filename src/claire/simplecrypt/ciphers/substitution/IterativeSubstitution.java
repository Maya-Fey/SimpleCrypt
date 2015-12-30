package claire.simplecrypt.ciphers.substitution;

import claire.simplecrypt.standards.ICipher;

public class IterativeSubstitution 
	   implements ICipher<SubstitutionKey> {

	private char[] key;
	private char[] alphabet;
	
	private int eshift = 0;
	private int dshift = 0;
	
	private SubstitutionKey master;
	
	public IterativeSubstitution(SubstitutionKey key)
	{
		this.key = key.getKey();
		this.alphabet = key.getAlphabet();
		this.master = key;
	}
	
	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			final char c = plaintext[start];
			for(int i = 0; i < alphabet.length; i++)
				if(c == alphabet[i]) {
					i += eshift++;
					if(eshift == alphabet.length)
						eshift = 0;
					plaintext[start] = key[i >= alphabet.length ? i - alphabet.length : i];
					break;
				}
			start++;
		}
	}

	public void encipher(char[] plaintext, int start0, char[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			final char c = plaintext[start0++];
			for(int i = 0; i < alphabet.length; i++)
				if(c == alphabet[i]) {
					i += eshift++;
					if(eshift == alphabet.length)
						eshift = 0;
					ciphertext[start1] = key[i >= alphabet.length ? i - alphabet.length : i];
					break;
				}
			start1++;
		}
	}
	
	public void decipher(char[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			final char c = ciphertext[start];
			for(int i = 0; i < alphabet.length; i++)
				if(c == key[i]) {
					i -= dshift++;
					if(dshift == alphabet.length)
						dshift = 0;
					ciphertext[start] = alphabet[i < 0 ? i + alphabet.length : i];
					break;
				}
			start++;
		}
	}

	public void decipher(char[] ciphertext, int start0, char[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			final char c = ciphertext[start0++];
			for(int i = 0; i < alphabet.length; i++)
				if(c == key[i]) {
					i -= dshift++;
					if(dshift == alphabet.length)
						dshift = 0;
					plaintext[start1] = alphabet[i < 0 ? i + alphabet.length : i];
					break;
				}
			start1++;
		}
	}

	public void reset() 
	{
		eshift = 0;
		dshift = 0;
	}

	public void setKey(SubstitutionKey key)
	{
		this.key = key.getKey();
		this.alphabet = key.getAlphabet();
		this.master = key;
		eshift = 0;
		dshift = 0;
	}

	public void destroy()
	{
		this.key = null;
		this.alphabet = null;
		this.key = null;
		eshift = 0;
		dshift = 0;
	}

	public SubstitutionKey getKey()
	{
		return this.master;
	}

}
