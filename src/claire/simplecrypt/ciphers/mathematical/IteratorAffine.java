package claire.simplecrypt.ciphers.mathematical;

import claire.simplecrypt.standards.ICipher;

public class IteratorAffine 
	   implements ICipher<IteratorAffineKey> {
	
	private IteratorAffineKey key;
	private int add;
	private int iterator;
	private int mul;
	private int inv;
	private int eadd = 0;
	private int dadd = 0;
	private char[] alphabet;
	
	public IteratorAffine(IteratorAffineKey key)
	{
		this.key = key;
		this.iterator = key.getIterator();
		this.add = key.getAdd();
		this.mul = key.getMul();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
	}

	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == plaintext[start])
					break;
			int n = ((j * mul) + add + eadd) % alphabet.length;
			eadd += iterator;
			if(eadd > alphabet.length)
				eadd -= alphabet.length;
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
			int n = ((j * mul) + add + eadd) % alphabet.length;
			eadd += iterator;
			if(eadd > alphabet.length)
				eadd -= alphabet.length;
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
			int n = ((j - add - dadd) * inv) % alphabet.length;
			n = n < 0 ? n + alphabet.length : n;
			dadd += iterator;
			if(dadd > alphabet.length)
				dadd -= alphabet.length;
			ciphertext[start++] = alphabet[n];
		}
	}

	public void decipher(char[] ciphertext, int start0, char[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == ciphertext[start0])
					break;
			int n = ((j - add - dadd) * inv) % alphabet.length;
			n = n < 0 ? n + alphabet.length : n;
			dadd += iterator;
			if(dadd > alphabet.length)
				dadd -= alphabet.length;
			start0++;
			plaintext[start1++] = alphabet[n];
		}
	}
	
	public void reset() 
	{
		this.eadd = 0;
		this.dadd = 0;
	}

	public void setKey(IteratorAffineKey key)
	{
		this.eadd = 0;
		this.dadd = 0;
		this.key = key;
		this.add = key.getAdd();
		this.iterator = key.getIterator();
		this.mul = key.getMul();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.eadd = 0;
		this.dadd = 0;
		this.iterator = key.getIterator();
		this.add = 0;
		this.mul = 0;
		this.inv = 0;
		this.alphabet = null;
	}

	public IteratorAffineKey getKey()
	{
		return this.key;
	}

}
