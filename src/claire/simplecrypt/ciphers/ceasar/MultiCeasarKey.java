package claire.simplecrypt.ciphers.ceasar;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.KeyFactory;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.crypto.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiCeasarKey
	   implements ISecret<MultiCeasarKey> {

	private Alphabet alphabet;
	private int[] key;
	
	public MultiCeasarKey(Alphabet alphabet, String key)
	{
		this.alphabet = alphabet;
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
	
	public MultiCeasarKey(Alphabet alphabet, int[] key)
	{
		this.alphabet = alphabet;
		this.key = key;
	}
	
	int[] getKey()
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
		Arrays.fill(key, 0);
		this.key = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.MULTICEASARKEY;
	}
	
	public boolean sameAs(MultiCeasarKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && ArrayUtil.equals(this.key, obj.key);
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeIntArr(key);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.getID(), bytes, offset); offset += 4;
		IOUtils.writeArr(key, bytes, offset);
	}

	public int exportSize()
	{
		return 8 + (key.length * 4);
	}

	public Factory<MultiCeasarKey> factory()
	{
		return factory;
	}
	
	public static MultiCeasarKey random(Alphabet alphabet, int size, IRandom<?, ?> rand)
	{
		int[] arr = new int[size];
		for(int i = 0; i < size; i++)
			arr[i] = rand.nextIntGood(alphabet.getLen());
		return new MultiCeasarKey(alphabet, arr);
	}
	
	public static final MultiCeasarKeyFactory factory = new MultiCeasarKeyFactory();
	
	private static final class MultiCeasarKeyFactory extends KeyFactory<MultiCeasarKey>
	{

		protected MultiCeasarKeyFactory() 
		{
			super(MultiCeasarKey.class);
		}

		public MultiCeasarKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet ab = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int[] key = new int[Bits.intFromBytes(data, start)]; start += 4;
			Bits.bytesToInts(data, start, key, 0);
			return new MultiCeasarKey(ab, key);
		}
		
		public MultiCeasarKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			Alphabet ab = stream.resurrect(Alphabet.factory);
			int[] key = new int[stream.readInt()];
			stream.readInts(key);
			return new MultiCeasarKey(ab, key);
		}
		
		public MultiCeasarKey random(Alphabet ab, IRandom<?, ?> rand)
		{
			return MultiCeasarKey.random(ab, 2 + rand.nextIntGood(7), rand);
		}
		
	}

}
