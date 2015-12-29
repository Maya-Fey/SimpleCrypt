package claire.simplecrypt.ciphers.substitution;

import claire.simplecrypt.standards.ICipher;

public class SubstitutionCipher 
	   implements ICipher<SubstitutionKey> {

	private char[] key;
	private char[] inv;
	private char[] alphabet;
	
	private SubstitutionKey master;
	
	public SubstitutionCipher(SubstitutionKey key)
	{
		this.key = key.getKey();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
		this.master = key;
	}
	
	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
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
			final char c = ciphertext[start];
			for(int i = 0; i < alphabet.length; i++)
				if(c == alphabet[i]) {
					ciphertext[start] = inv[i];
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
				if(c == alphabet[i]) {
					ciphertext[start1] = inv[i];
					break;
				}
			start1++;
		}
	}

	public void reset() {}

	public void setKey(SubstitutionKey key)
	{
		this.key = key.getKey();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
		this.master = key;
	}

	public void destroy()
	{
		this.key = null;
		this.inv = null;
		this.alphabet = null;
		this.key = null;
	}

	public SubstitutionKey getKey()
	{
		return this.master;
	}

}
