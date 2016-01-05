package claire.simplecrypt.ciphers.mathematical;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ISecret;
import claire.simplecrypt.standards.NamespaceKey;
import claire.util.io.Factory;
import claire.util.io.IOUtils;
import claire.util.math.MathHelper;
import claire.util.memory.Bits;
import claire.util.memory.util.ArrayUtil;
import claire.util.standards.IRandom;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public class MultiAffineKey
	   implements ISecret<MultiAffineKey> {

	private Alphabet alphabet;
	private int[] key;
	private int[] mul;
	private int[] inv;
	
	public MultiAffineKey(Alphabet alphabet, int[] key, int[] mul, int[] inv)
	{
		this.alphabet = alphabet;
		this.key = key;
		this.mul = mul;
		this.inv = inv;
	}
	
	int[] getMul()
	{
		return this.mul;
	}
	
	int[] getInv()
	{
		return this.inv;
	}
	
	int[] getAdd()
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
		Arrays.fill(mul, 0);
		Arrays.fill(inv, 0);
		this.key = null;
		this.mul = null;
		this.inv = null;
	}
	
	public int NAMESPACE()
	{
		return NamespaceKey.MULTIAFFINEKEY;
	}

	public boolean sameAs(MultiAffineKey obj)
	{
		return this.alphabet.getID() == obj.alphabet.getID() && (ArrayUtil.equals(this.key, obj.key) && ArrayUtil.equals(this.mul, obj.mul));
	}

	public void export(IOutgoingStream stream) throws IOException
	{
		stream.persist(alphabet);
		stream.writeIntArr(key);
		stream.writeIntArr(mul);
		stream.writeIntArr(inv);
	}

	public void export(byte[] bytes, int offset)
	{
		alphabet.export(bytes, offset); offset += 4;
		offset = IOUtils.writeArr(key, bytes, offset);
		offset = IOUtils.writeArr(mul, bytes, offset);
		IOUtils.writeArr(inv, bytes, offset);
	}

	public int exportSize()
	{
		return (12 * key.length) + 16;
	}

	public Factory<MultiAffineKey> factory()
	{
		return factory;
	}
	
	public static MultiAffineKey random(Alphabet alphabet, int size, IRandom rand)
	{
		final int mod = alphabet.getLen();
		final int max = mod - 1;
		int start = 0;
		int[] add = new int[size];
		int[] mul = new int[size];
		int[] inv = new int[size];
		while(size-- > 0)
		{
			add[start] = rand.nextIntGood(max);
			int mult;
			while(true) {
				mult = 1 + rand.nextIntGood(alphabet.getLen() - 1);
				if(MathHelper.gcd(mult, mod) == 1) {
					inv[start  ] = MathHelper.modular_inverse(mult, mod);
					mul[start++] = mult; 
					break;
				}
			}
		}
		return new MultiAffineKey(alphabet, add, mul, inv);
	}
	
	private static final AffineKeyFactory factory = new AffineKeyFactory();
	
	private static final class AffineKeyFactory extends Factory<MultiAffineKey>
	{

		protected AffineKeyFactory() 
		{
			super(MultiAffineKey.class);
		}

		public MultiAffineKey resurrect(byte[] data, int start) throws InstantiationException
		{
			Alphabet alphabet = Alphabet.fromID(Bits.intFromBytes(data, start)); start += 4;
			int[] add = IOUtils.readIntArr(data, start);
			int size = add.length * 4 + 4; start += size;
			int[] mul = IOUtils.readIntArr(data, start); start += size;
			return new MultiAffineKey(alphabet, add, mul,IOUtils.readIntArr(data, start));
		}
		
		public MultiAffineKey resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return new MultiAffineKey(stream.resurrect(Alphabet.factory), stream.readIntArr(), stream.readIntArr(), stream.readIntArr());
		}
		
	}

}
