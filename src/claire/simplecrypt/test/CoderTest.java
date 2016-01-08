package claire.simplecrypt.test;

import claire.simplecrypt.data.Alphabet;
import claire.simplecrypt.standards.ICharCoder;
import claire.util.logging.Log;
import claire.util.memory.util.ArrayUtil;

final class CoderTest {
	
	private static final char[] AB = Alphabet.SIMPLELAB.getChars();
	
	public static final int runTest()
	{
		Log.info.println();
		Log.info.println("----------------------------------");
		Log.info.println("Testing coders");
		int fails = 0;
		for(int i = 0; i < Test.coders.length; i++)
		{
			ICharCoder coder = Test.coders[i];
			Log.info.println("Testing " + coder.getClass().getSimpleName());
			try {
				char[] plain = new char[80];
				for(int j = 0; j < 80; j++) 
					plain[j] = AB[Test.rng.nextIntFast(AB.length)];
				
				char[] s1 = ArrayUtil.copy(plain);
				char[] s2 = new char[80];
				coder.encode(s1, 20, 60);
				Test.scipher.reset();
				coder.encode(plain, 20, s2, 20, 60);
				for(int j = 20; j < 80; j++) {
					if(s1[j] != s2[j]) {
						fails++;
						Log.err.println("In-Place encoding gives different results then copy enciphering for " + coder.getClass().getSimpleName());
						Log.err.println(s1);
						Log.err.println(s2);
						break;
					}
				}
				char[] s3 = new char[80];
				coder.decode(s1, 20, 60);
				Test.scipher.reset();
				coder.decode(s2, 20, s3, 20, 60);
				for(int j = 20; j < 80; j++) {
					if(s1[j] != s3[j]) {
						fails++;
						Log.err.println("In-Place decoding gives different results then copy enciphering for " + coder.getClass().getSimpleName());
						Log.err.println(s1);
						Log.err.println(s3);
						break;
					}
				}
				for(int j = 20; j < 80; j++) {
					if((s1[j] & s3[j]) != plain[j]) {
						fails++;
						Log.err.println("One or both decoding methods did not return the original plaintext for " + coder.getClass().getSimpleName());
						Log.err.println(plain);
						Log.err.println(s1);
						Log.err.println(s3);
						break;
					}
				}
			} catch(Exception e) {
				fails++;
				Log.err.println("Encountered unexpexted exception while testing " + coder.getClass().getSimpleName());
				Log.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
			}
		}
		return fails;
	}

}
