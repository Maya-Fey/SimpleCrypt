package claire.simplecrypt.ciphers.mathematical;

import claire.simplecrypt.standards.ICipher;

public class AffineCipher 
	   implements ICipher<AffineKey> {
	
	private AffineKey key;
	private int add;
	private int mul;
	private int inv;
	private char[] alphabet;
	
	public AffineCipher(AffineKey key)
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
			int n = ((j * mul) + add) % alphabet.length;
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
			int n = ((j * mul) + add) % alphabet.length;
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
			int n = ((j - add) * inv) % alphabet.length;
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
			int n = ((j - add) * inv) % alphabet.length;
			n = n < 0 ? n + alphabet.length : n;
			plaintext[start1++] = alphabet[n];
		}
	}
	
	public void reset() {}

	public void setKey(AffineKey key)
	{
		this.key = key;
		this.add = key.getAdd();
		this.mul = key.getMul();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.add = 0;
		this.mul = 0;
		this.inv = 0;
		this.alphabet = null;
	}

	public AffineKey getKey()
	{
		return this.key;
	}

}
