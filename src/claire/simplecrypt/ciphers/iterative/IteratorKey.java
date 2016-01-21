package claire.simplecrypt.ciphers.iterative;

import java.io.IOException;

import claire.simplecrypt.ciphers.KeyFactory;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IteratorKey
	   implements ISecret<IteratorKey> {

	private Alphabet alphabet;
	private int key;
	
	public IteratorKey(Alphabet alphabet, int key)
	{
		this.alphabet = alphabet;
		this.key = key;
	}
	
	int getKey()
	{
		return this.key;
	}
	
	public Alphabet getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		this.alphabet = null;
		this.key = 0;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.ITERATORKEY;
	}

	public boolean sameAs(IteratorKey obj)
	{
		return this.key == obj.key && this.alphabet.getID() == obj.alphabet.getID();
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeInt(key);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		Bits.intToBytes(key, bytes, offset); 
	}

	public int exportSize()
	{
		return 8;
	}

	public Factory<IteratorKey> factory()
	{
		return factory;
	}
	
	public static IteratorKey random(Alphabet alphabet, IRandom rand)
	{
		return new IteratorKey(alphabet, 1 + rand.nextIntGood(alphabet.getLen() - 1));
	}
	
	public static final IteratorKeyFactory factory = new IteratorKeyFactory();
	
	private static final class IteratorKeyFactory extends KeyFactory<IteratorKey>
	{

		protected IteratorKeyFactory() 
		{
			super(IteratorKey.class);
		}

		public IteratorKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			return new IteratorKey(alphabet, Bits.intFromBytes(data, start));
		}
		
		public IteratorKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new IteratorKey(stream.resurrect(Alphabet.factory), stream.readInt());
		}

		public IteratorKey random(Alphabet ab, IRandom rand)
		{
			return IteratorKey.random(ab, rand);
		}
		
	}

}
