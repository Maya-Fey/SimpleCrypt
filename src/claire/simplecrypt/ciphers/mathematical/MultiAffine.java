package claire.simplecrypt.ciphers.mathematical;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class MultiAffine 
	   implements ICipher<MultiAffineKey> {
	
	private MultiAffineKey key;
	private Alphabet alphabet;
	private int epos = 0;
	private int dpos = 0;
	private int[] add;
	private int[] mul;
	private int[] inv;
	
	
	public MultiAffine(MultiAffineKey key)
	{
		this.key = key;
		this.add = key.getAdd();
		this.mul = key.getMul();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
	}

	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = (plaintext[start] * mul[epos]) + add[epos++];
			if(n >= alphabet.getLen())
				n %= alphabet.getLen();
			if(epos == add.length)
				epos = 0;
			plaintext[start++] = (byte) n;
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = (plaintext[start0++] * mul[epos]) + add[epos++];
			if(n >= alphabet.getLen())
				n %= alphabet.getLen();
			if(epos == add.length)
				epos = 0;
			ciphertext[start1++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = (ciphertext[start] - add[dpos]);
			if(n < 0)
				n += alphabet.getLen();
			n *= inv[dpos++];
			n %= alphabet.getLen();
			if(dpos == add.length)
				dpos = 0;
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = (ciphertext[start0++] - add[dpos]);
			if(n < 0)
				n += alphabet.getLen();
			n *= inv[dpos++];
			n %= alphabet.getLen();
			if(dpos == add.length)
				dpos = 0;
			plaintext[start1++] = (byte) n;
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
