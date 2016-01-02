package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.crypto.rng.RandUtils;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiIteratorSubstitutionKey 
	   implements ISecret<MultiIteratorSubstitutionKey> {
	
	private char[][] key;	
	private int iterator;
	private Alphabet alphabet;
	
	public MultiIteratorSubstitutionKey(char[][] key, int iterator, Alphabet alphabet)
	{
		this.iterator = iterator;
		this.alphabet = alphabet;
		this.key = key;
	}
	
	int getIterator()
	{
		return iterator;
	}
	
	char[][] getKey()
	{
		return this.key;
	}
	
	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		for(char[] c : key)
			Arrays.fill(c, (char) 0);
		key = null;
		alphabet = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.MULTIITERATORSUBSTITUTIONKEY;
	}
	
	public boolean sameAs(MultiIteratorSubstitutionKey obj)
	{
		if(this.key.length != obj.key.length)
			return false;
		for(int i = 0; i < this.key.length; i++) 
			if(!ArrayUtil.equals(this.key[i], obj.key[i]))
				return false;
		return this.alphabet.getID() == obj.alphabet.getID();
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(iterator);
		stream.writeInt(key.length);
		stream.writeInt(key[0].length);
		for(char[] c : key)
			stream.writeChars(c);
		stream.persist(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(iterator, bytes, offset); offset += 4;
		Bits.intToBytes(key.length, bytes, offset); offset += 4;
		Bits.intToBytes(key[0].length, bytes, offset); offset += 4;
		final int size = key[0].length * 2;
		final int len = key[0].length;
		for(char[] c : key) {
			Bits.charsToBytes(c, 0, bytes, offset, len);
			offset += size;
		}
		alphabet.export(bytes, offset);
	}
	
	public int exportSize()
	{
		return (alphabet.getLen() * key.length * 2) + 16;
	}

	public Factory<MultiIteratorSubstitutionKey> factory()
	{
		return factory;
	}
	
	private static final Factory<MultiIteratorSubstitutionKey> factory = new SubstitutionKeyFactory();
	
	private static final class SubstitutionKeyFactory extends Factory<MultiIteratorSubstitutionKey>
	{

		protected SubstitutionKeyFactory()
		{
			super(MultiIteratorSubstitutionKey.class);
		}

		public MultiIteratorSubstitutionKey resurrect(byte[] data, int start) throws InstantiationException
		{
			int iterator = Bits.intFromBytes(data, start); start += 4;
			int s1 = Bits.intFromBytes(data, start); start += 4;
			int s2 = Bits.intFromBytes(data, start); start += 4;
			int size = s2 * 2;
			char[][] key = new char[s1][s2];
			for(char[] c : key) {
				Bits.bytesToChars(data, start, c, 0, s2);
				start += size;
			}
			Alphabet alphabet = Alphabet.factory.resurrect(data, start);
			return new MultiIteratorSubstitutionKey(key, iterator, alphabet);
		}

		public MultiIteratorSubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int iterator = stream.readInt();
			char[][] key = new char[stream.readInt()][stream.readInt()];
			for(char[] c : key)
				stream.readChars(c);
			Alphabet alphabet = stream.resurrect(Alphabet.factory);
			return new MultiIteratorSubstitutionKey(key, iterator, alphabet);
		}
		
	}
	
	public static final char[] getInv(final char[] key, final char[] alphabet)
	{
		char[] inv = new char[key.length];
		for(int i = 0; i < key.length; i++) {
			for(int j = 0; j < key.length; j++)
				if(alphabet[i] == key[j]) {
					inv[i] = alphabet[j];
					break;
				}
		}
		return inv;
	}
	
	public static final MultiIteratorSubstitutionKey random(Alphabet alphabet, int size, IRandom rng)
	{
		final char[] ab = alphabet.getChars();
		char[][] key = new char[size][alphabet.getLen()];
		for(char[] c : key) {
			System.arraycopy(ab, 0, c, 0, ab.length);
			RandUtils.randomize(c, rng);
		}
		return new MultiIteratorSubstitutionKey(key, 1 + rng.nextIntGood(alphabet.getLen() - 1), alphabet);
	}

}
