package claire.simplecrypt.ciphers.substitution;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;

public class MultiSubstitution 
	   implements ICipher<MultiSubstitutionKey> {

	private byte[][] key;
	private byte[][] inv;
	private Alphabet alphabet;
	
	private int ekey = 0;
	private int dkey = 0;
	
	private MultiSubstitutionKey master;
	
	public MultiSubstitution(MultiSubstitutionKey key)
	{
		this.key = key.getKey();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
		this.master = key;
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			byte[] key = this.key[ekey++];
			if(ekey == this.key.length)
				ekey = 0;
			plaintext[start] = key[plaintext[start++]];
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			byte[] key = this.key[ekey++];
			if(ekey == this.key.length)
				ekey = 0;
			ciphertext[start1++] = key[plaintext[start0++]];
		}
	}
	
	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			byte[] inv = this.inv[dkey++];
			if(dkey == this.key.length)
				dkey = 0;
			ciphertext[start] = inv[ciphertext[start++]];
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			byte[] inv = this.inv[dkey++];
			if(dkey == this.key.length)
				dkey = 0;
			plaintext[start1++] = inv[ciphertext[start0++]];
		}
	}


	public void reset() 
	{
		this.ekey = 0;
		this.dkey = 0;
	}

	public void setKey(MultiSubstitutionKey key)
	{
		this.key = key.getKey();
		this.inv = key.getInv();
		this.alphabet = key.getAlphabet();
		this.master = key;
		this.ekey = 0;
		this.dkey = 0;
	}

	public void destroy()
	{
		this.key = null;
		this.inv = null;
		this.alphabet = null;
		this.key = null;
		this.ekey = 0;
		this.dkey = 0;
	}

	public MultiSubstitutionKey getKey()
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
