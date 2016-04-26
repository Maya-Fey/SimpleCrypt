package claire.simplecrypt.ciphers.feistel;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.ciphers.KeyFactory;
import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.crypto.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class FeistelKey
	   implements ISecret<FeistelKey> {
	
	private Alphabet alphabet;
	private byte[] key;
	
	public FeistelKey(Alphabet alpha, byte[] key)
	{
		this.alphabet = alpha;
		this.key = key;
	}
	
	public byte[] getKey()
	{
		return this.key;
	}
	
	public Alphabet getAlphabet()
	{
		return this.alphabet;
	}

	public void destroy()
	{
		Arrays.fill(key, (byte) 0);
		this.alphabet = null;
		this.key = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.FEISTELKEY;
	}
	
	public boolean sameAs(FeistelKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && ArrayUtil.equals(this.key, obj.key);
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(this.alphabet);
		stream.writeByteArr(key);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(alphabet.getID(), bytes, offset); offset += 4;
		Bits.intToBytes(key.length, bytes, offset); offset += 4;
		System.arraycopy(key, 0, bytes, offset, key.length);
	}

	public int exportSize()
	{
		return 8 + key.length;
	}

	public KeyFactory<FeistelKey> factory()
	{
		return factory;
	}
	
	public static final FeistelKeyFactory factory = new FeistelKeyFactory();

	private static final class FeistelKeyFactory extends KeyFactory<FeistelKey> {

		public FeistelKeyFactory() 
		{
			super(FeistelKey.class);
		}

		public FeistelKey random(Alphabet ab, IRandom<?> rand)
		{
			byte[] bytes = new byte[2 + rand.nextIntGood(8)];
			for(int i = 0; i < bytes.length; i++)
				bytes[i] = (byte) rand.nextIntGood(ab.getLen());
			return new FeistelKey(ab, bytes);
		}

		public FeistelKey resurrect(byte[] data, int start) throws InstantiationException
		{
			int ab = Bits.intFromBytes(data, start); start += 4;
			byte[] bytes = new byte[Bits.intFromBytes(data, start)]; start += 4;
			System.arraycopy(data, start, bytes, 0, bytes.length);
			return new FeistelKey(Alphabet.fromID(ab), bytes);
		}

		public FeistelKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new FeistelKey(stream.resurrect(Alphabet.factory), stream.readByteArr());
		}
		
	}
	
	public static final FeistelKey random(Alphabet ab, IRandom<?> rand)
	{
		byte[] bytes = new byte[2 + rand.nextIntGood(8)];
		for(int i = 0; i < bytes.length; i++)
			bytes[i] = (byte) rand.nextIntGood(ab.getLen());
		return new FeistelKey(ab, bytes);
	}

}
