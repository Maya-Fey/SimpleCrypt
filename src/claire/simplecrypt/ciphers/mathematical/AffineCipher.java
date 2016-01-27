package claire.simplecrypt.ciphers.mathematical;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;

public class AffineCipher 
	   implements ICipher<AffineKey, IState<?>> {
	
	private AffineKey key;
	private Alphabet alphabet;
	private int add;
	private int mul;
	private int inv;
	
	public AffineCipher(AffineKey key)
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
			int n = (plaintext[start] * mul) + add;
			if(n >= alphabet.getLen())
				n %= alphabet.getLen();
			plaintext[start++] = (byte) n;
		}
	}

	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = (plaintext[start0++] * mul) + add;
			if(n >= alphabet.getLen())
				n %= alphabet.getLen();
			ciphertext[start1++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = (ciphertext[start] - add);
			if(n < 0)
				n += alphabet.getLen();
			n *= inv;
			n %= alphabet.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = (ciphertext[start0++] - add) * inv;
			if(n < 0)
				n += alphabet.getLen();
			n *= inv;
			n %= alphabet.getLen();
			plaintext[start1++] = (byte) n;
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

	public void loadState(IState<?> state) {}
	public void updateState(IState<?> state) {}
	
	public IState<?> getState()
	{
		return null;
	}

	public boolean hasState()
	{
		return false;
	}

}
