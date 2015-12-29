package claire.simplecrypt.ciphers.ceasar;

import claire.simplecrypt.standards.ICipher;

public class MultiCeasar 
	   implements ICipher<MultiCeasarKey> {
	
	private MultiCeasarKey key;
	private int[] shifts;
	private int epos = 0;
	private int dpos = 0;
	private char[] alphabet;
	
	public MultiCeasar(MultiCeasarKey key)
	{
		this.key = key;
		this.shifts = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void encipher(char[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int j = 0;
			for(; j <= alphabet.length; j++)
				if(alphabet[j] == plaintext[start])
					break;
			int n = j + shifts[epos++];
			if(epos == shifts.length)
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
			int n = j + shifts[epos++];
			if(epos == shifts.length)
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
			int n = j - shifts[dpos++];
			if(dpos == shifts.length)
				dpos = 0;
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
			int n = j - shifts[dpos++];
			if(dpos == shifts.length)
				dpos = 0;
			start0++;
			plaintext[start1++] = alphabet[n < 0 ? n + alphabet.length : n];
		}
	}
	
	public void reset() 
	{
		this.epos = 0;
		this.dpos = 0;
	}

	public void setKey(MultiCeasarKey key)
	{
		this.key = key;
		this.epos = 0;
		this.dpos = 0;
		this.shifts = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.epos = 0;
		this.dpos = 0;
		this.alphabet = null;
		this.shifts = null;
	}

	public MultiCeasarKey getKey()
	{
		return this.key;
	}

}
