package claire.simplecrypt.ciphers.iterative;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class IterativeCipher 
	   implements ICipher<IteratorKey> {

	private IteratorKey master;
	private Alphabet ab;
	private int eadd;
	private int dadd;
	
	public IterativeCipher(IteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		eadd = dadd = key.getKey();
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + eadd++;
			if(eadd == ab.getLen())
				eadd = 0;
			if(n >= ab.getLen())
				n -= ab.getLen();
			plaintext[start++] = (byte) n;
		}
	}
	
	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start0++] + eadd++;
			if(eadd == ab.getLen())
				eadd = 0;
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
		dadd = eadd = master.getKey();
	}

	public void setKey(IteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		dadd = eadd = key.getKey();
	}

	public void destroy()
	{
		master = null;
		ab = null;
		dadd = eadd = 0;
	}

	public IteratorKey getKey()
	{
		return master;
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start] - dadd++;
			if(dadd == ab.getLen())
				dadd = 0;
			if(n < 0)
				n += ab.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start0++] - dadd++;
			if(dadd == ab.getLen())
				dadd = 0;
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
