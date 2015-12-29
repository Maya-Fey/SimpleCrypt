package claire.simplecrypt.ciphers.ceasar;

import claire.simplecrypt.standards.ICipher;

public class CeasarCipher 
	   implements ICipher<CeasarKey> {
	
	private CeasarKey key;
	private int shift;
	private char[] alphabet;
	
	public CeasarCipher(CeasarKey key)
	{
		this.key = key;
		this.shift = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == plaintext[start])
					break;
			int n = j + shift;
			plaintext[start++] = alphabet[n >= alphabet.length ? n % alphabet.length : n];
		}
	}

	public void encipher(char[] plaintext, int start0, char[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == plaintext[start0])
					break;
			int n = j + shift;
			start0++;
			ciphertext[start1++] = alphabet[n >= alphabet.length ? n % alphabet.length : n];
		}
	}

	public void decipher(char[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == ciphertext[start])
					break;
			int n = j - shift;
			ciphertext[start++] = alphabet[n < 0 ? n + alphabet.length : n];
		}
	}

	public void decipher(char[] ciphertext, int start0, char[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == ciphertext[start0])
					break;
			int n = j - shift;
			start0++;
			plaintext[start1++] = alphabet[n < 0 ? n + alphabet.length : n];
		}
	}
	
	public void reset() {}

	public void setKey(CeasarKey key)
	{
		this.key = key;
		this.shift = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.shift = 0;
		this.alphabet = null;
	}

	public CeasarKey getKey()
	{
		return this.key;
	}

}
