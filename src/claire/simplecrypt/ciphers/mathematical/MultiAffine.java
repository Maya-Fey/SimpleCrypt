package claire.simplecrypt.ciphers.mathematical;

import claire.simplecrypt.standards.ICipher;

public class MultiAffine 
	   implements ICipher<MultiAffineKey> {
	
	private MultiAffineKey key;
	private int epos = 0;
	private int dpos = 0;
	private int[] add;
	private int[] mul;
	private int[] inv;
	private char[] alphabet;
	
	public MultiAffine(MultiAffineKey key)
	{
		this.key = key;
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
			int n = ((j * mul[epos]) + add[epos++]) % alphabet.length;
			if(epos == add.length)
				epos = 0;
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
			int n = ((j * mul[epos]) + add[epos++]) % alphabet.length;
			if(epos == add.length)
				epos = 0;
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
			int n = ((j - add[dpos]) * inv[dpos++]) % alphabet.length;
			if(dpos == add.length)
				dpos = 0;
			n = n < 0 ? n + alphabet.length : n;
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
			int n = ((j - add[dpos]) * inv[dpos++]) % alphabet.length;
			if(dpos == add.length)
				dpos = 0;
			n = n < 0 ? n + alphabet.length : n;
			start0++;
			plaintext[start1++] = alphabet[n];
		}
	}
	
	public void reset() 
	{
		epos = 0;
		dpos = 0;
	}

	public void setKey(MultiAffineKey key)
	{
		this.key = key;
		epos = 0;
		dpos = 0;
		this.add = key.getAdd();
		this.mul = key.getMul();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		epos = 0;
		dpos = 0;
		this.add = null;
		this.mul = null;
		this.inv = null;
		this.alphabet = null;
	}

	public MultiAffineKey getKey()
	{
		return this.key;
	}

}
