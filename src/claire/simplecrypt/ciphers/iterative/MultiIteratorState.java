package claire.simplecrypt.ciphers.iterative;

import java.io.IOException;

import claire.simplecrypt.standards.IState;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
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
		this.eadd = c.eadd;
		this.dadd = c.dadd;
		this.epos = c.epos;
		this.dpos = c.dpos;
	}
	
	public MultiIteratorState(MultiIterative c)
	{
		this.eadd = c.eadd;
		this.dadd = c.dadd;
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
		offset = IOUtils.writeArr(eadd, bytes, offset);
		IOUtils.writeArr(dadd, bytes, offset);
	}

	public int exportSize()
	{
		return 4 * eadd.length + 12;
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
			int[] ek = IOUtils.readIntArr(data, start); start += 4 * len;
			int[] dk = IOUtils.readIntArr(data, start); 
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
	
	