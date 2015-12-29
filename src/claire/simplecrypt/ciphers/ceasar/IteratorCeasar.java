package claire.simplecrypt.ciphers.ceasar;

import claire.simplecrypt.standards.ICipher;

public class IteratorCeasar 
	   implements ICipher<IteratorCeasarKey> {
	
	private IteratorCeasarKey key;
	private int eshift;
	private int dshift;
	private char[] alphabet;
	private int iterator;
	
	public IteratorCeasar(IteratorCeasarKey key)
	{
		this.key = key;
		this.eshift = key.getKey();
		this.dshift = key.getKey();
		this.alphabet = key.getAlphabet();
		this.iterator = key.getIterator();
	}
	
	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == plaintext[start])
					break;
			int n = j + eshift;
			eshift += iterator;
			eshift %= alphabet.length;
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
			int n = j + eshift;
			eshift += iterator;
			eshift %= alphabet.length;
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
			int n = j - dshift;
			dshift += iterator;
			dshift %= alphabet.length;
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
			int n = j - dshift;
			dshift += iterator;
			dshift %= alphabet.length;
			start0++;
			plaintext[start1++] = alphabet[n < 0 ? n + alphabet.length : n];
		}
	}
	
	public void reset() 
	{
		this.eshift = key.getKey();
		this.dshift = key.getKey();
	}

	public void setKey(IteratorCeasarKey key)
	{
		this.key = key;
		this.eshift = key.getKey();
		this.dshift = key.getKey();
		this.alphabet = key.getAlphabet();
		this.iterator = key.getIterator();
	}

	public void destroy()
	{
		this.eshift = 0;
		this.dshift = 0;
		this.alphabet = null;
		this.iterator = 0;
	}

	public IteratorCeasarKey getKey()
	{
		return this.key;
	}

}
