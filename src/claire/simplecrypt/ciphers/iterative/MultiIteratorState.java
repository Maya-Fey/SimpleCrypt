package claire.simplecrypt.ciphers.iterative;

import java.io.IOException;

import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiIteratorState 
	   implements IState<MultiIteratorState> {
	
	protected final int[] eadd;
	protected final int[] dadd;
	
	protected int epos;
	protected int dpos;
	
	private MultiIteratorState(int epos, int dpos, int[] eadd, int[] dadd)
	{
		this.epos = epos;
		this.dpos = dpos;
		this.eadd = eadd;
		this.dadd = dadd;
	}
		
	public MultiIteratorState(MultiIterator c)
	{
		this.eadd = ArrayUtil.copy(c.eadd);
		this.dadd = ArrayUtil.copy(c.dadd);
		this.epos = c.epos;
		this.dpos = c.dpos;
	}
	
	public MultiIteratorState(MultiIterative c)
	{
		this.eadd = ArrayUtil.copy(c.eadd);
		this.dadd = ArrayUtil.copy(c.dadd);
		this.epos = c.epos;
		this.dpos = c.dpos;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.MULTIITERATORSTATE;
	}

	public boolean sameAs(MultiIteratorState obj)
	{
		return (epos == obj.dpos && obj.epos == obj.dpos) && (ArrayUtil.equals(eadd, obj.eadd) && ArrayUtil.equals(dadd, obj.dadd));
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(epos);
		stream.writeInt(dpos);
		stream.writeInt(eadd.length);
		stream.writeInts(eadd);
		stream.writeInts(dadd);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(epos, bytes, offset); offset += 4;
		Bits.intToBytes(dpos, bytes, offset); offset += 4;
		Bits.intToBytes(eadd.length, bytes, offset); offset += 4;
		Bits.intsToBytes(eadd, 0, bytes, offset, eadd.length); offset += 4 * eadd.length;
		Bits.intsToBytes(dadd, 0, bytes, offset, dadd.length);
	}

	public int exportSize()
	{
		return 8 * eadd.length + 12;
	}

	public Factory<MultiIteratorState> factory()
	{
		return sfactory;
	}
	
	public static final MultiIteratorStateFactory sfactory = new MultiIteratorStateFactory();
	
	private static final class MultiIteratorStateFactory extends Factory<MultiIteratorState>
	{

		protected MultiIteratorStateFactory() 
		{
			super(MultiIteratorState.class);
		}

		public MultiIteratorState resurrect(byte[] data, int start) throws InstantiationException
		{
			int ep = Bits.intFromBytes(data, start); start += 4;
			int dp = Bits.intFromBytes(data, start); start += 4;
			int len = Bits.intFromBytes(data, start); start += 4;
			int[] ek = new int[len];
			int[] dk = new int[len];
			Bits.bytesToInts(data, start, ek, 0, len); start += len * 4;
			Bits.bytesToInts(data, start, dk, 0, len); 
			return new MultiIteratorState(ep, dp, ek, dk);
		}

		public MultiIteratorState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int ep = stream.readInt();
			int dp = stream.readInt();
			int[] ek = stream.readIntArr();
			int[] dk = stream.readInts(ek.length);
			return new MultiIteratorState(ep, dp, ek, dk);
		}
		
	}

}
	
	