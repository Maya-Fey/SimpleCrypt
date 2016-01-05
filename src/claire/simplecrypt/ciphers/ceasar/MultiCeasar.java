package claire.simplecrypt.ciphers.ceasar;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class MultiCeasar 
	   implements ICipher<MultiCeasarKey> {
	
	private MultiCeasarKey key;
	private Alphabet alphabet;
	private int[] shifts;
	private int epos = 0;
	private int dpos = 0;
	
	public MultiCeasar(MultiCeasarKey key)
	{
		this.key = key;
		this.shifts = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + shifts[epos++];
			if(epos == shifts.length)
				epos = 0;
			if(n >= alphabet.getLen())
				n -= alphabet.getLen();
			plaintext[start++] = (byte) n;
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start0++] + shifts[epos++];
			if(epos == shifts.length)
				epos = 0;
			if(n >= alphabet.getLen())
				n -= alphabet.getLen();
			ciphertext[start1++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start] - shifts[dpos++];
			if(dpos == shifts.length)
				dpos = 0;
			if(n < 0)
				n += alphabet.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start0++] - shifts[dpos++];
			if(dpos == shifts.length)
				dpos = 0;
			if(n < 0)
				n += alphabet.getLen();
			plaintext[start1++] = (byte) n;
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
	
	public int ciphertextSize(int plain)
	{
		return plain;
	}

	public int plaintextSize(int cipher)
	{
		return cipher;
	}

	public Alphabet getAlphabet()
	{
		return alphabet;
	}

}
