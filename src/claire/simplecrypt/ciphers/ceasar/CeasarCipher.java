package claire.simplecrypt.ciphers.ceasar;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;

public class CeasarCipher 
	   implements ICipher<CeasarKey, IState<?>> {
	
	private CeasarKey key;
	private Alphabet alphabet;
	private int shift;
	
	public CeasarCipher(CeasarKey key)
	{
		this.key = key;
		this.shift = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + shift;
			if(n >= alphabet.getLen())
				n -= alphabet.getLen();
			plaintext[start++] = (byte) n;
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start0++] + shift;
			if(n >= alphabet.getLen())
				n -= alphabet.getLen();
			ciphertext[start1++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start] - shift;
			if(n < 0)
				n += alphabet.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start0] - shift;
			if(n < 0)
				n += alphabet.getLen();
			plaintext[start1++] = (byte) n;
		}
	}
	
	public void reset() {}

	public void setKey(CeasarKey key)
	{
		this.key = key;
		this.shift = key.getKey();
		this.alphabet = key.getAlphabet();
	}

	public void destroy()
	{
		this.shift = 0;
		this.alphabet = null;
	}

	public CeasarKey getKey()
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
	
	public void updateState(IState<?> state) {}
	public void loadState(IState<?> state) {}

	public IState<?> getState()
	{
		return null;
	}

	public boolean hasState()
	{
		return false;
	}

}
