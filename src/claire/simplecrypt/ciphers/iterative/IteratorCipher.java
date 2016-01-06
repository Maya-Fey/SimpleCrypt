package claire.simplecrypt.ciphers.iterative;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class IteratorCipher 
	   implements ICipher<IteratorKey> {

	private IteratorKey master;
	private Alphabet ab;
	private int iterator;
	private int eadd = 0;
	private int dadd = 0;
	
	public IteratorCipher(IteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		iterator = key.getKey();
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + eadd;
			eadd += iterator;
			if(eadd >= ab.getLen())
				eadd -= ab.getLen();
			if(n >= ab.getLen())
				n -= ab.getLen();
			plaintext[start++] = (byte) n;
		}
	}
	
	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start0++] + eadd;
			eadd += iterator;
			if(eadd >= ab.getLen())
				eadd -= ab.getLen();
			if(n >= ab.getLen())
				n -= ab.getLen();
			ciphertext[start1++] = (byte) n;
		}
	}
	
	public int ciphertextSize(int plain)
	{
		return plain;
	}

	public void reset()
	{
		dadd = eadd = 0;
	}

	public void setKey(IteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		iterator = key.getKey();
		dadd = eadd = 0;
	}

	public void destroy()
	{
		master = null;
		ab = null;
		dadd = eadd = iterator = 0;
	}

	public IteratorKey getKey()
	{
		return master;
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start] - dadd;
			dadd += iterator;
			if(dadd >= ab.getLen())
				dadd -= ab.getLen();
			if(n < 0)
				n += ab.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start0++] - dadd;
			dadd += iterator;
			if(dadd >= ab.getLen())
				dadd -= ab.getLen();
			if(n < 0)
				n += ab.getLen();
			plaintext[start1++] = (byte) n;
		}
	}

	public int plaintextSize(int cipher)
	{
		return cipher;
	}

	public Alphabet getAlphabet()
	{
		return ab;
	}

}
