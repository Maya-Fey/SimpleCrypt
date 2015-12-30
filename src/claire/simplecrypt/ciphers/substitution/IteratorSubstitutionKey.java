package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.crypto.rng.RandUtils;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class IteratorSubstitutionKey 
	   implements ISecret<IteratorSubstitutionKey> {
	
	private int iterator;
	private char[] key;	
	private Alphabet alphabet;
	
	public IteratorSubstitutionKey(char[] key, int iterator, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.iterator = iterator;
		this.key = key;
	}
	
	int getIterator()
	{
		return this.iterator;
	}
	
	char[] getKey()
	{
		return this.key;
	}
	
	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		Arrays.fill(key, (char) 0);
		key = null;
		iterator = 0;
		alphabet = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.ITERATORSUBSTITUTIONKEY;
	}
	
	public boolean sameAs(IteratorSubstitutionKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && ArrayUtil.equals(this.key, obj.key);
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeCharArr(key);
		stream.writeInt(iterator);
		stream.persist(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		offset = IOUtils.writeArr(key, bytes, offset);
		Bits.intToBytes(iterator, bytes, offset); offset += 4;
		alphabet.export(bytes, offset);
	}
	
	public int exportSize()
	{
		return alphabet.getLen() * 2 + 12;
	}

	public Factory<IteratorSubstitutionKey> factory()
	{
		return factory;
	}
	
	private static final Factory<IteratorSubstitutionKey> factory = new SubstitutionKeyFactory();
	
	private static final class SubstitutionKeyFactory extends Factory<IteratorSubstitutionKey>
	{

		protected SubstitutionKeyFactory()
		{
			super(IteratorSubstitutionKey.class);
		}

		public IteratorSubstitutionKey resurrect(byte[] data, int start) throws InstantiationException
		{
			char[] key = IOUtils.readCharArr(data, start);
			start += key.length * 2 + 4;
			int iterator = Bits.intFromBytes(data, start); start += 4;
			Alphabet alphabet = Alphabet.factory.resurrect(data, start);
			return new IteratorSubstitutionKey(key, iterator, alphabet);
		}

		public IteratorSubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] key = stream.readCharArr();
			int iterator = stream.readInt();
			Alphabet alphabet = stream.resurrect(Alphabet.factory);
			return new IteratorSubstitutionKey(key, iterator, alphabet);
		}
		
	}
	
	public static final IteratorSubstitutionKey random(Alphabet alphabet, IRandom rng)
	{
		char[] key = ArrayUtil.copy(alphabet.getChars());
		RandUtils.randomize(key, rng);
		return new IteratorSubstitutionKey(key, 1 + rng.nextIntGood(key.length - 1), alphabet);
	}

}
