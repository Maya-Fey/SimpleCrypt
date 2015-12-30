package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.crypto.rng.RandUtils;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class SubstitutionKey 
	   implements ISecret<SubstitutionKey> {
	
	private char[] key;
	private char[] inv;
	
	private Alphabet alphabet;
	
	public SubstitutionKey(char[] key, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = getInv(key, alphabet.getChars());
	}
	
	protected SubstitutionKey(char[] key, char[] inv, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = inv;
	}
	
	char[] getKey()
	{
		return this.key;
	}
	
	char[] getInv()
	{
		return this.inv;
	}

	public char[] getAlphabet()
	{
		return this.alphabet.getChars();
	}

	public void destroy()
	{
		Arrays.fill(key, (char) 0);
		Arrays.fill(inv, (char) 0);
		key = null;
		inv = null;
		alphabet = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.SUBSTITUTIONKEY;
	}
	
	public boolean sameAs(SubstitutionKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && ArrayUtil.equals(this.key, obj.key);
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeCharArr(key);
		stream.writeCharArr(inv);
		stream.persist(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		offset = IOUtils.writeArr(key, bytes, offset);
		offset = IOUtils.writeArr(inv, bytes, offset);
		alphabet.export(bytes, offset);
	}
	
	public int exportSize()
	{
		return alphabet.getLen() * 4 + 12;
	}

	public Factory<SubstitutionKey> factory()
	{
		return factory;
	}
	
	private static final Factory<SubstitutionKey> factory = new SubstitutionKeyFactory();
	
	private static final class SubstitutionKeyFactory extends Factory<SubstitutionKey>
	{

		protected SubstitutionKeyFactory()
		{
			super(SubstitutionKey.class);
		}

		public SubstitutionKey resurrect(byte[] data, int start) throws InstantiationException
		{
			char[] key = IOUtils.readCharArr(data, start);
			int size = key.length * 2 + 4;
			start += size;
			char[] inv = IOUtils.readCharArr(data, start);
			start += size;
			Alphabet alphabet = Alphabet.factory.resurrect(data, start);
			return new SubstitutionKey(key, inv, alphabet);
		}

		public SubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			char[] key = stream.readCharArr();
			char[] inv = stream.readCharArr();
			Alphabet alphabet = stream.resurrect(Alphabet.factory);
			return new SubstitutionKey(key, inv, alphabet);
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
	
	public static final SubstitutionKey random(Alphabet alphabet, IRandom rng)
	{
		char[] key = ArrayUtil.copy(alphabet.getChars());
		RandUtils.randomize(key, rng);
		char[] inv = getInv(key, alphabet.getChars());
		return new SubstitutionKey(key, inv, alphabet);
	}

}
