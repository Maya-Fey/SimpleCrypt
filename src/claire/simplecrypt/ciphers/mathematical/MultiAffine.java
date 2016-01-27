package claire.simplecrypt.ciphers.mathematical;

import java.io.IOException;

import claire.simplecrypt.ciphers.mathematical.MultiAffine.MultiAffineState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiAffine 
	   implements ICipher<MultiAffineKey, MultiAffineState> {
	
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
	
	public void loadState(MultiAffineState state)
	{
		this.epos = state.epos;
		this.dpos = state.dpos;
	}
	
	public void updateState(MultiAffineState state)
	{
		state.epos = this.epos;
		state.dpos = this.dpos;
	}

	public MultiAffineState getState()
	{
		return new MultiAffineState(this);
	}

	public boolean hasState()
	{
		return true;
	}
	
	public static final MultiAffineStateFactory sfactory = new MultiAffineStateFactory();
	
	public static final class MultiAffineState implements IState<MultiAffineState>
	{
		private int epos;
		private int dpos;
		
		public MultiAffineState(MultiAffine c)
		{
			epos = c.epos;
			dpos = c.dpos;
		}
		
		public MultiAffineState(int e, int d)
		{
			this.epos = e;
			this.dpos = d;
		}

		public int NAMESPACE()
		{
			return NamespaceKey.MULTIAFFINESTATE;
		}
		
		public boolean sameAs(MultiAffineState obj)
		{
			return epos == obj.epos && dpos == obj.dpos;
		}
		
		public void export(IOutgoingStream stream) throws IOException
		{
			stream.writeInt(epos);
			stream.writeInt(dpos);
		}

		public void export(byte[] bytes, int offset)
		{
			Bits.intToBytes(epos, bytes, offset); offset += 4;
			Bits.intToBytes(dpos, bytes, offset);
		}

		public int exportSize()
		{
			return 8;
		}

		public Factory<MultiAffineState> factory()
		{
			return sfactory;
		}
		
	}
	
	private static final class MultiAffineStateFactory extends Factory<MultiAffineState>
	{

		protected MultiAffineStateFactory() 
		{
			super(MultiAffineState.class);
		}

		public MultiAffineState resurrect(byte[] data, int start) throws InstantiationException
		{
			int e = Bits.intFromBytes(data, start); start += 4;
			return new MultiAffineState(e, Bits.intFromBytes(data, start));
		}

		public MultiAffineState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new MultiAffineState(stream.readInt(), stream.readInt());
		}
		
	}

}
