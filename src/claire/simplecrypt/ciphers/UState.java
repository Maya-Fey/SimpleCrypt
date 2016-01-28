package claire.simplecrypt.ciphers;

import java.io.IOException;

import claire.simplecrypt.standards.IState;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IPersistable;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class UState implements IPersistable<UState> {

	private final int ID;
	private final IState<?> state;
	
	public UState(IState<?> state, int ID) 
	{
		this.state = state;
		this.ID = ID;
	}
	
	public int getID()
	{
		return this.ID;
	}
	
	public IState<?> getState()
	{
		return this.state;
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(ID);
		stream.persist(state);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(ID, bytes, offset);
		state.export(bytes, offset + 4);
	}

	public int exportSize()
	{
		return state.exportSize() + 4;
	}

	public Factory<UState> factory()
	{
		return factory;
	}
	
	public static final Factory<UState> factory = new UKeyFactory();
	
	private static final class UKeyFactory extends Factory<UState> {

		protected UKeyFactory() 
		{
			super(UState.class);
		}

		public UState resurrect(byte[] data, int start) throws InstantiationException
		{
			int ID = Bits.intFromBytes(data, start);
			Factory<? extends IState<?>> factory = CipherRegistry.getStateFactory(ID);
			return new UState(factory.resurrect(data, start + 4), ID);
		}

		public UState resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int ID = stream.readInt();
			return new UState(stream.resurrect(CipherRegistry.getStateFactory(ID)), ID);
		}
		
	}

}
