package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;

import claire.simplecrypt.ciphers.ceasar.MultiCeasar.MultiCeasarState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiCeasar 
	   implements ICipher<MultiCeasarKey, MultiCeasarState> {
	
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
	
	public void loadState(MultiCeasarState state)
	{
		this.epos = state.epos;
		this.dpos = state.dpos;
	}
	
	public void updateState(MultiCeasarState state)
	{
		state.epos = this.epos;
		state.dpos = this.dpos;
	}

	public MultiCeasarState getState()
	{
		return new MultiCeasarState(this);
	}

	public boolean hasState()
	{
		return true;
	}
	
	public static final MultiCeasarStateFactory sfactory = new MultiCeasarStateFactory();
	
	protected static final class MultiCeasarState implements IState<MultiCeasarState>
	{
		private int epos;
		private int dpos;
		
		public MultiCeasarState(MultiCeasar c)
		{
			epos = c.epos;
			dpos = c.dpos;
		}
		
		public MultiCeasarState(int e, int d)
		{
			this.epos = e;
			this.dpos = d;
		}

		public int NAMESPACE()
		{
			return NamespaceKey.MULTICEASARSTATE;
		}
		
		public boolean sameAs(MultiCeasarState obj)
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

		public Factory<MultiCeasarState> factory()
		{
			return sfactory;
		}
		
	}
	
	private static final class MultiCeasarStateFactory extends Factory<MultiCeasarState>
	{

		protected MultiCeasarStateFactory() 
		{
			super(MultiCeasarState.class);
		}

		public MultiCeasarState resurrect(byte[] data, int start) throws InstantiationException
		{
			int e = Bits.intFromBytes(data, start); start += 4;
			return new MultiCeasarState(e, Bits.intFromBytes(data, start));
		}

		public MultiCeasarState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new MultiCeasarState(stream.readInt(), stream.readInt());
		}
		
	}

}
