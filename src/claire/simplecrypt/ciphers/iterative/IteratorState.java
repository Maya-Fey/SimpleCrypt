package claire.simplecrypt.ciphers.iterative;

import java.io.IOException;

import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IteratorState implements IState<IteratorState> {

	protected int dadd;
	protected int eadd;
	
	public IteratorState(IterativeCipher c) 
	{
		eadd = c.eadd;
		dadd = c.dadd;
	}

	public IteratorState(IteratorCipher c) 
	{
		eadd = c.eadd;
		dadd = c.dadd;
	}
	
	public IteratorState(int e, int d)
	{
		eadd = e;
		dadd = d;
	}

	public int NAMESPACE()
	{
		return NamespaceKey.ITERATORSTATE;
	}

	public boolean sameAs(IteratorState obj)
	{
		return eadd == obj.eadd && dadd == obj.dadd;
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(eadd);
		stream.writeInt(dadd);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(eadd, bytes, offset); offset += 4;
		Bits.intToBytes(dadd, bytes, offset);
	}

	public int exportSize()
	{
		return 8;
	}

	public Factory<IteratorState> factory()
	{
		return factory;
	}
	
	public static final IteratorStateFactory factory = new IteratorStateFactory();
	
	private static final class IteratorStateFactory extends Factory<IteratorState>
	{

		protected IteratorStateFactory() 
		{
			super(IteratorState.class);
		}

		public IteratorState resurrect(byte[] data, int start) throws InstantiationException
		{
			int e = Bits.intFromBytes(data, start); start += 4;
			return new IteratorState(e, Bits.intFromBytes(data, start));
		}

		public IteratorState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new IteratorState(stream.readInt(), stream.readInt());
		}
		
	}
	
}
