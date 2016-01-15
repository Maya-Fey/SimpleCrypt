package claire.simplecrypt.ciphers;

import java.io.IOException;

import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IPersistable;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class UKey implements IPersistable<UKey> {

	private final int ID;
	private final ISecret<?> key;
	
	public UKey(ISecret<?> key, int ID) 
	{
		this.key = key;
		this.ID = ID;
	}
	
	public int getID()
	{
		return this.ID;
	}
	
	public ISecret<?> getKey()
	{
		return this.key;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(ID);
		stream.persist(key);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(ID, bytes, offset);
		key.export(bytes, offset + 4);
	}

	public int exportSize()
	{
		return key.exportSize() + 4;
	}

	public Factory<UKey> factory()
	{
		return factory;
	}
	
	public static final Factory<UKey> factory = new UKeyFactory();
	
	private static final class UKeyFactory extends Factory<UKey> {

		protected UKeyFactory() 
		{
			super(UKey.class);
		}

		public UKey resurrect(byte[] data, int start) throws InstantiationException
		{
			int ID = Bits.intFromBytes(data, start);
			Factory<? extends ISecret<?>> factory = CipherRegistry.getFactory(ID);
			return new UKey(factory.resurrect(data, start + 4), ID);
		}

		public UKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int ID = stream.readInt();
			return new UKey(stream.resurrect(CipherRegistry.getFactory(ID)), ID);
		}
		
	}

}
