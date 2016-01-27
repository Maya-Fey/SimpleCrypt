package claire.simplecrypt.test;

import java.io.IOException;
import java.util.Arrays;

import claire.util.io.Factory;
import claire.util.logging.Log;
import claire.util.memory.buffer.ByteArrayIncomingStream;
import claire.util.memory.buffer.ByteArrayOutgoingStream;
import claire.util.standards.IPersistable;
import claire.util.standards.IUUID;

final class PersistTest {
	
	public static final int runTest() 
	{
		Log.info.println();
		Log.info.println("----------------------------------");
		Log.info.println("Testing key persistence.");
		int fails = 0;
		for(int i = 0; i < Test.keys.length; i++) 
			fails += test(Test.keys[i]);
		Log.info.println();
		Log.info.println("----------------------------------");
		Log.info.println("Testing state persistence.");
		for(int i = 0; i < Test.states.length; i++) 
			fails += test(Test.states[i]);
		return fails;
	}
	
	@SuppressWarnings("unchecked")
	public static <Type extends IPersistable<?> & IUUID<?>> int test(Type sec)
	{
		int fails = 0;
		try {
			Log.info.println("Testing " + sec.getClass().getSimpleName());
			Factory<Type> factory = (Factory<Type>) sec.factory();
			
			/*
			 * Raw bytes
			 */
			byte[] bytes = sec.export();
			try {
				Type cmp = factory.resurrect(bytes);
				if(!cmp.equals(sec)) {
					fails++;
					Log.err.println("When ressurrecting from raw bytes instances of " + sec.getClass().getSimpleName() + " are not equal.");
				}
			} catch (InstantiationException e) {
				fails++;
				Log.err.println("Encountered InstantiationException while resurrecting from raw bytes for " + sec.getClass().getSimpleName());
			}
			
			
			/*
			 * Raw bytes with offset
			 */
			bytes = new byte[sec.exportSize() + 20];
			sec.export(bytes, 20);
			try {
				Type cmp = factory.resurrect(bytes, 20);
				if(!cmp.equals(sec)) {
					fails++;
					Log.err.println("When ressurrecting from raw bytes with offset instances of " + sec.getClass().getSimpleName() + " are not equal.");
				}
			} catch (InstantiationException e) {
				fails++;
				Log.err.println("Encountered InstantiationException while resurrecting from raw bytes with offset for " + sec.getClass().getSimpleName());
			}
			
			boolean fail = true;
			try {
				sec.export(bytes, 21);
			} catch(ArrayIndexOutOfBoundsException e) {
				fail = false;
			}
			if(fail) {
				fails++;
				Log.err.println("Export size reported by " + sec.getClass().getSimpleName() + " is different then actual size");
			}
			
			/*
			 * Streams
			 */
			Arrays.fill(bytes, (byte) 0);
			try {
				ByteArrayOutgoingStream os = new ByteArrayOutgoingStream(bytes);
				sec.export(os);
				os.close();
				ByteArrayIncomingStream is = new ByteArrayIncomingStream(bytes);
				try {
					Type cmp = factory.resurrect(is);
					if(!cmp.equals(sec)) {
						fails++;
						Log.err.println("When ressurrecting from stream instances of " + sec.getClass().getSimpleName() + " are not equal.");
					}
				} catch (InstantiationException e) {
					fails++;
					Log.err.println("Encountered InstantiationException while resurrecting from streams for " + sec.getClass().getSimpleName());
				}
				is.close();
			} catch(IOException e) {
				fails++;
				Log.err.println("Encountered IOException while persisting and resurrecting from streams with " + sec.getClass().getSimpleName());
			}
		} catch(Exception e) {
			fails++;
			Log.err.println("Unexpected exception while testing " + sec.getClass().getSimpleName());
			Log.err.println(e.getClass().getSimpleName() + ": " + e.getMessage());
		}
		return fails;
	}

}
