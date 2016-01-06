package claire.simplecrypt.ciphers.iterative;

import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;

public class MultiIterative 
	   implements ICipher<MultiIteratorKey> {

	private MultiIteratorKey master;
	private Alphabet ab;
	private int[] eadd;
	private int[] dadd;
	private int epos = 0;
	private int dpos = 0;
	
	public MultiIterative(MultiIteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		int[] ints = key.getKey();
		eadd = new int[ints.length];
		dadd = new int[ints.length];
		System.arraycopy(ints, 0, eadd, 0, ints.length);
		System.arraycopy(ints, 0, dadd, 0, ints.length);
	}
	
	public void encipher(byte[] plaintext, int start, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start] + eadd[epos]++;
			if(eadd[epos] == ab.getLen())
				eadd[epos] = 0;
			if(++epos == eadd.length)
				epos = 0;
			if(n >= ab.getLen())
				n -= ab.getLen();
			plaintext[start++] = (byte) n;
		}
	}
	
	public void encipher(byte[] plaintext, int start0, byte[] ciphertext, int start1, int len)
	{
		while(len-- > 0) {
			int n = plaintext[start0++] + eadd[epos]++;
			if(eadd[epos] == ab.getLen())
				eadd[epos] = 0;
			if(++epos == eadd.length)
				epos = 0;
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
		epos = dpos = 0;
		int[] ints = master.getKey();
		System.arraycopy(ints, 0, eadd, 0, ints.length);
		System.arraycopy(ints, 0, dadd, 0, ints.length);
	}

	public void setKey(MultiIteratorKey key)
	{
		master = key;
		ab = key.getAlphabet();
		int[] ints = master.getKey();
		if(ints.length != eadd.length) {
			eadd = new int[ints.length];
			dadd = new int[ints.length];
		}
		System.arraycopy(ints, 0, eadd, 0, ints.length);
		System.arraycopy(ints, 0, dadd, 0, ints.length);
		epos = dpos = 0;
	}

	public void destroy()
	{
		master = null;
		ab = null;
		dpos = epos = 0;
		Arrays.fill(eadd, 0);
		Arrays.fill(dadd, 0);
		eadd = dadd = null;
	}

	public MultiIteratorKey getKey()
	{
		return master;
	}

	public void decipher(byte[] ciphertext, int start, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start] - dadd[dpos]++;
			if(dadd[dpos] == ab.getLen())
				dadd[dpos] = 0;
			if(++dpos == dadd.length)
				dpos = 0;
			if(n < 0)
				n += ab.getLen();
			ciphertext[start++] = (byte) n;
		}
	}

	public void decipher(byte[] ciphertext, int start0, byte[] plaintext, int start1, int len)
	{
		while(len-- > 0) {
			int n = ciphertext[start0++] - dadd[dpos]++;
			if(dadd[dpos] == ab.getLen())
				dadd[dpos] = 0;
			if(++dpos == dadd.length)
				dpos = 0;
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
