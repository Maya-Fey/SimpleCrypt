package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiIteratorCeasarKey
	   implements ISecret<MultiIteratorCeasarKey> {

	private Alphabet alphabet;
	private int[] key;
	private int iterator;
	
	public MultiIteratorCeasarKey(Alphabet alphabet, String key, int iterator)
	{
		this.alphabet = alphabet;
		this.iterator = iterator;
		this.key = new int[key.length()];
		char[] chars = alphabet.getChars();
		for(int i = 0; i < key.length(); i++) {
			char c = key.charAt(i);
			for(int j = 0; j <= chars.length; j++)
				if(c == chars[j]) {
					this.key[i] = j;
					break;
				}
		}
	}
	
	public MultiIteratorCeasarKey(Alphabet alphabet, int[] key, int iterator)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.iterator = iterator;
	}
	
	int[] getKey()
	{
		return this.key;
	}
	
	int getIterator()
	{
		return this.iterator;
	}
	
	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		this.alphabet = null;
		Arrays.fill(key, 0);
		this.key = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.MULTIITERATORCEASARKEY;
	}
	
	public boolean sameAs(MultiIteratorCeasarKey obj)
	{
		return (this.alphabet.getID() == obj.alphabet.getID() && this.iterator == obj.iterator) && ArrayUtil.equals(this.key, obj.key);
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeIntArr(key);
		stream.writeInt(iterator);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		offset = IOUtils.writeArr(key, bytes, offset);
		Bits.intToBytes(iterator, bytes, offset);
	}

	public int exportSize()
	{
		return 12 + (key.length * 4);
	}

	public Factory<MultiIteratorCeasarKey> factory()
	{
		return factory;
	}
	
	public static MultiIteratorCeasarKey random(Alphabet alphabet, int size, IRandom rand)
	{
		final int len = alphabet.getLen();
		int[] arr = new int[size];
		for(int i = 0; i < size; i++)
			arr[i] = rand.nextIntFast(len);
		return new MultiIteratorCeasarKey(alphabet, arr, 1 + rand.nextIntFast(len - 1));
	}
	
	private static final MultiCeasarKeyFactory factory = new MultiCeasarKeyFactory();
	
	private static final class MultiCeasarKeyFactory extends Factory<MultiIteratorCeasarKey>
	{

		protected MultiCeasarKeyFactory() 
		{
			super(MultiIteratorCeasarKey.class);
		}

		public MultiIteratorCeasarKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet ab = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int[] key = IOUtils.readIntArr(data, start); start += key.length * 4 + 4;
			return new MultiIteratorCeasarKey(ab, key, Bits.intFromBytes(data, start));
		}
		
		public MultiIteratorCeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			Alphabet ab = stream.resurrect(Alphabet.factory);
			int[] key = stream.readIntArr();
			return new MultiIteratorCeasarKey(ab, key, stream.readInt());
		}
		
	}

}
