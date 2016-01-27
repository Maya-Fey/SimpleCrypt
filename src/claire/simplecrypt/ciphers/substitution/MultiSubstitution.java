package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;

import claire.simplecrypt.ciphers.substitution.MultiSubstitution.MultiSubstitutionState;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICipher;
import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiSubstitution 
	   implements ICipher<MultiSubstitutionKey, MultiSubstitutionState> {

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
	
	public void loadState(MultiSubstitutionState state)
	{
		this.ekey = state.ekey;
		this.dkey = state.dkey;
	}
	
	public void updateState(MultiSubstitutionState state)
	{
		state.ekey = this.ekey;
		state.dkey = this.dkey;
	}

	public MultiSubstitutionState getState()
	{
		return new MultiSubstitutionState(this);
	}

	public boolean hasState()
	{
		return true;
	}
	
	public static final MultiSubstitutionStateFactory sfactory = new MultiSubstitutionStateFactory();
	
	protected static final class MultiSubstitutionState implements IState<MultiSubstitutionState>
	{
		private int ekey;
		private int dkey;
		
		public MultiSubstitutionState(MultiSubstitution c)
		{
			ekey = c.ekey;
			dkey = c.dkey;
		}
		
		public MultiSubstitutionState(int e, int d)
		{
			this.ekey = e;
			this.dkey = d;
		}

		public int NAMESPACE()
		{
			return NamespaceKey.MULTIAFFINESTATE;
		}
		
		public boolean sameAs(MultiSubstitutionState obj)
		{
			return ekey == obj.ekey && dkey == obj.dkey;
		}
		
		public void export(IOutgoingStream stream) throws IOException
		{
			stream.writeInt(ekey);
			stream.writeInt(dkey);
		}

		public void export(byte[] bytes, int offset)
		{
			Bits.intToBytes(ekey, bytes, offset); offset += 4;
			Bits.intToBytes(dkey, bytes, offset);
		}

		public int exportSize()
		{
			return 8;
		}

		public Factory<MultiSubstitutionState> factory()
		{
			return sfactory;
		}
		
	}
	
	private static final class MultiSubstitutionStateFactory extends Factory<MultiSubstitutionState>
	{

		protected MultiSubstitutionStateFactory() 
		{
			super(MultiSubstitutionState.class);
		}

		public MultiSubstitutionState resurrect(byte[] data, int start) throws InstantiationException
		{
			int e = Bits.intFromBytes(data, start); start += 4;
			return new MultiSubstitutionState(e, Bits.intFromBytes(data, start));
		}

		public MultiSubstitutionState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new MultiSubstitutionState(stream.readInt(), stream.readInt());
		}
		
	}

}
