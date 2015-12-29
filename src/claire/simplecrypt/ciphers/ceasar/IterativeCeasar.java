package claire.simplecrypt.ciphers.ceasar;

import claire.simplecrypt.standards.ICipher;

public class IterativeCeasar 
	   implements ICipher<CeasarKey> {
	
	private CeasarKey key;
	private int eshift;
	private int dshift;
	private char[] alphabet;
	
	public IterativeCeasar(CeasarKey key)
	{
		this.key = key;
		this.eshift = key.getKey();
		this.dshift = key.getKey();
		this.alphabet = key.getAlphabet();
	}
	
	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == plaintext[start])
					break;
			int n = j + eshift++;
			if(eshift == alphabet.length)
				eshift = 0;
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
			int n = j + eshift++;
			if(eshift == alphabet.length)
				eshift = 0;
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
			int n = j - dshift++;
			if(dshift == alphabet.length)
				dshift = 0;
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
			int n = j - dshift++;
			if(dshift == alphabet.length)
				dshift = 0;
			start0++;
			plaintext[start1++] = alphabet[n < 0 ? n + alphabet.length : n];
		}
	}
	
	public void reset() 
	{
		this.eshift = key.getKey();
		this.dshift = key.getKey();
	}

	public void setKey(CeasarKey key)
	{
		this.key = key;
		this.eshift = key.getKey();
		this.dshift = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.eshift = 0;
		this.dshift = 0;
		this.alphabet = null;
	}

	public CeasarKey getKey()
	{
		return this.key;
	}

}
