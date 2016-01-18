package claire.simplecrypt.data;

import java.io.IOException;

import claire.util.io.Factory;
import claire.util.memory.Bits;
import claire.util.standards.IPersistable;
import claire.util.standards.io.IIncomingStream;
import claire.util.standards.io.IOutgoingStream;

public final class Alphabet
			 implements IPersistable<Alphabet> {
	
	private static final char[] ASIMPLEAB = new char[] 
		{
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
			'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
			'W', 'X', 'Y', 'Z'
		};
	
	private static final char[] ASIMPLELAB = new char[]
		{
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 
			'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 
			'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 
			'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 
			's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
		};
	
	private static final char[] ASPACEDAB = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z'
		};
	
	private static final char[] ASPACEDLAB = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
		};
	
	private static final char[] ASPACEDANUM = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5',
			'6', '7', '8', '9'
		};
	
	private static final char[] ASPACEDAPUNC = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', '.', ',', '?', '!', '(', ')',
			'/', '"', '\'', ':'
		};
	
	private static final char[] ASPACEDLANUM = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', 
			'2', '3', '4', '5', '6', '7', '8', '9'
		};
	
	private static final char[] ASPACEDLAPUNC = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '.', ',', 
			'?', '!', '(', ')', '/', '"', '\'', ':'
		};
	
	private static final char[] ASPACEDLANUMPUNC = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', 
			'2', '3', '4', '5', '6', '7', '8', '9', '.', ',', '?', 
			'!', '(', ')', '/',  '"', '\'', ':', '-'
		};

	private static final char[] AADVANCED = new char[]
		{
			' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 
			'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 
			'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
			'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', 
			'2', '3', '4', '5', '6', '7', '8', '9', '.', ',', '?', 
			'!', '(', ')', '/', '"', '\'', ':', '-', '>', '<', '%', 
			'$', '[', ']', '^', '&', '*', '+', '=',
		};	

	public static final Alphabet SIMPLEAB        = new Alphabet(ASIMPLEAB);
	public static final Alphabet SIMPLELAB       = new Alphabet(ASIMPLELAB);
	public static final Alphabet SPACEDAB        = new Alphabet(ASPACEDAB);
	public static final Alphabet SPACEDLAB       = new Alphabet(ASPACEDLAB);
	public static final Alphabet SPACEDANUM      = new Alphabet(ASPACEDANUM);
	public static final Alphabet SPACEDAPUNC     = new Alphabet(ASPACEDAPUNC);
	public static final Alphabet SPACEDLANUM     = new Alphabet(ASPACEDLANUM);
	public static final Alphabet SPACEDLAPUNC    = new Alphabet(ASPACEDLAPUNC);
	public static final Alphabet SPACEDLANUMPUNC = new Alphabet(ASPACEDLANUMPUNC);
	public static final Alphabet ADVANCED        = new Alphabet(AADVANCED);
	
	public static final Alphabet[] alphabets = new Alphabet[]
		{
			SIMPLEAB,
			SIMPLELAB,
			SPACEDAB,
			SPACEDLAB,
			SPACEDANUM,
			SPACEDAPUNC,
			SPACEDLANUM,
			SPACEDLAPUNC,
			SPACEDLANUMPUNC,
			ADVANCED
		};
	
	public static final String[] names = new String[]
		{
			"Simple Alphabet",
			"Cased Alphabet",
			"Simple Alphabet + Space",
			"Cased Alphabet + Space",
			"Simple Alphabet + Space + Numerals",
			"Simple Alphabet + Space + Punctuation",
			"Cased Alphabet + Space + Numerals",
			"Cased Alphabet + Space + Punctuation",
			"Cased Alphabet + Space + Numerals + Punctuation",
			"Advanced Alphabet"
		};
	
	public static final String[] alphastrings = new String[names.length];
	
	static 
	{
		for(int i = 0; i < alphabets.length; i++)
			alphastrings[i] = "[" + new String(alphabets[i].getChars()) + "]";
	}
	
	private static int CTR = 0;
	
	private final int ID;
	private final char[] chars;
	
	private Alphabet(char[] arr)
	{
		this.chars = arr;
		this.ID = CTR++;
	}
	
	public int getID()
	{
		return this.ID;
	}
	
	public int getLen()
	{
		return chars.length;
	}
	
	public char[] getChars()
	{
		return this.chars;
	}
	
	public byte convertTo(char in)
	{
		for(int i = 0; i < this.chars.length; i++)
			if(chars[i] == in)
				return (byte) i;
		return -1;
	}
	
	public void convertTo(char[] chars, int start0, byte[] rep, int start1, int len)
	{
		while(len-- > 0) {
			for(int i = 0; i <= this.chars.length; i++) {
				if(this.chars[i] == chars[start0]) {
					rep[start1++] = (byte) i;
					break;
				}
			}
			start0++;
		}
	}
	public void convertToUnsafe(char[] chars, int start0, byte[] rep, int start1, int len)
	{
		while(len-- > 0) {
			byte v = -1;
			for(int i = 0; i < this.chars.length; i++) {
				if(this.chars[i] == chars[start0]) {
					v = (byte) i;
					break;
				}
			}
			rep[start1++] = v;
			start0++;
		}
	}
	
	public char convertFrom(byte in)
	{
		return chars[in];
	}
	
	public void convertFrom(byte[] rep, int start0, char[] chars, int start1, int len)
	{
		while(len-- > 0) 
			chars[start1++] = this.chars[rep[start0++]];
	}
	
	public boolean contains(char c)
	{
		for(char c2 : chars)
			if(c == c2)
				return true;
		return false;
	}
	
	public void export(IOutgoingStream stream) throws IOException
	{
		stream.writeInt(ID);
	}

	public void export(byte[] bytes, int offset)
	{
		Bits.intToBytes(ID, bytes, offset);
	}

	public int exportSize()
	{
		return 4;
	}

	public Factory<Alphabet> factory()
	{
		return factory;
	}
	
	public static final AlphabetFactory factory = new AlphabetFactory();
	
	public static final class AlphabetFactory extends Factory<Alphabet>
	{

		protected AlphabetFactory() 
		{
			super(Alphabet.class);
		}

		public Alphabet resurrect(byte[] data, int start) throws InstantiationException
		{
			return fromID(Bits.intFromBytes(data, start));
		}

		public Alphabet resurrect(IIncomingStream stream) throws InstantiationException, IOException
		{
			return fromID(stream.readInt());
		}
		
	}
	
	public static Alphabet fromID(int id)
	{
		return alphabets[id];
	}
	
	public static String nameFromID(int id)
	{
		return names[id];
	}
	
	public static String repFromID(int id)
	{
		return alphastrings[id];
	}

}
