package claire.simplecrypt.ciphers.substitution;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class SubstitutionCipher 
	   implements ICipher<SubstitutionKey> {

	private byte[] key;
	private byte[] inv;
	
	private Alphabet alphabet;
	private SubstitutionKey master;
	
	public SubstitutionCipher(SubstitutionKey key)
	{
		this.key = key.getKey();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
		this.master = key;
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) 
			plaintext[start] = key[plaintext[start++]];
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) 
			ciphertext[start1++] = key[plaintext[start0++]];
	}
	
	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) 
			ciphertext[start] = inv[ciphertext[start++]];
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) 
			plaintext[start1++] = inv[ciphertext[start0++]];
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
