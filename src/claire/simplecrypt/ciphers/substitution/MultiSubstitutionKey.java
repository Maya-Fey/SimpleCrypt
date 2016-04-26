package claire.simplecrypt.ciphers.substitution;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.KeyFactory;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.crypto.rng.RandUtils;
import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.crypto.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiSubstitutionKey 
	   implements ISecret<MultiSubstitutionKey> {
	
	private byte[][] key;	
	private byte[][] inv;	
	private Alphabet alphabet;
	
	public MultiSubstitutionKey(byte[][] key, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = new byte[key.length][];
		for(int i = 0; i < key.length; i++)
			inv[i] = SubstitutionKey.getInv(key[i]);
	}
	
	public MultiSubstitutionKey(byte[][] key, byte[][] inv, Alphabet alphabet)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.inv = inv;
	}
	
	byte[][] getKey()
	{
		return this.key;
	}
	
	byte[][] getInv()
	{
		return this.inv;
	}
	
	public Alphabet getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		for(byte[] c : key)
			Arrays.fill(c, (byte) 0);
		for(byte[] c : inv)
			Arrays.fill(c, (byte) 0);
		alphabet = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.MULTISUBSTITUTIONKEY;
	}
	
	public boolean sameAs(MultiSubstitutionKey obj)
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
		stream.writeInt(key.length);
		stream.writeInt(key[0].length);
		for(byte[] c : key)
			stream.writeBytes(c);
		for(byte[] c : inv)
			stream.writeBytes(c);
		stream.persist(alphabet);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(key.length, bytes, offset); offset += 4;
		Bits.intToBytes(key[0].length, bytes, offset); offset += 4;
		final int size = key[0].length;
		final int len = key[0].length;
		for(byte[] c : key) {
			System.arraycopy(c, 0, bytes, offset, len);
			offset += size;
		}
		for(byte[] c : inv) {
			System.arraycopy(c, 0, bytes, offset, len);
			offset += size;
		}
		alphabet.export(bytes, offset);
	}
	
	public int exportSize()
	{
		return (alphabet.getLen() * key.length * 2) + 12;
	}

	public Factory<MultiSubstitutionKey> factory()
	{
		return factory;
	}
	
	public static final MultiSubstitutionKeyFactory factory = new MultiSubstitutionKeyFactory();
	
	private static final class MultiSubstitutionKeyFactory extends KeyFactory<MultiSubstitutionKey>
	{

		protected MultiSubstitutionKeyFactory()
		{
			super(MultiSubstitutionKey.class);
		}

		public MultiSubstitutionKey resurrect(byte[] data, int start) throws InstantiationException
		{
			int s1 = Bits.intFromBytes(data, start); start += 4;
			int s2 = Bits.intFromBytes(data, start); start += 4;
			byte[][] key = new byte[s1][s2];
			byte[][] inv = new byte[s1][s2];
			for(byte[] c : key) {
				System.arraycopy(data, start, c, 0, s2);
				start += s2;
			}
			for(byte[] c : inv) {
				System.arraycopy(data, start, c, 0, s2);
				start += s2;
			}
			Alphabet alphabet = Alphabet.factory.resurrect(data, start);
			return new MultiSubstitutionKey(key, inv, alphabet);
		}

		public MultiSubstitutionKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			int s1 = stream.readInt();
			int s2 = stream.readInt();
			byte[][] key = new byte[s1][s2];
			byte[][] inv = new byte[s1][s2];
			for(byte[] c : key)
				stream.readBytes(c);
			for(byte[] c : inv)
				stream.readBytes(c);
			Alphabet alphabet = stream.resurrect(Alphabet.factory);
			return new MultiSubstitutionKey(key, inv, alphabet);
		}

		public MultiSubstitutionKey random(Alphabet ab, IRandom<?> rand)
		{
			return MultiSubstitutionKey.random(ab, 2 + rand.nextIntGood(7), rand);
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
	
	public static final MultiSubstitutionKey random(Alphabet alphabet, int size, IRandom<?> rng)
	{
		byte[][] key = new byte[size][alphabet.getLen()];
		for(int i = 0; i < size; i++) {
			byte[] arr = key[i];
			for(int j = 0; j < arr.length; j++)
				arr[j] = (byte) j;
			RandUtils.randomize(arr, rng);
		}
		return new MultiSubstitutionKey(key, alphabet);
	}

}
