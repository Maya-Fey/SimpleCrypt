package claire.simplecrypt.test;

import java.io.IOException;
import java.util.Arrays;

import claire.simplecrypt.standards.ISecret;
import claire.util.io.Factory;
import claire.util.logging.Log;
import claire.util.memory.buffer.ByteArrayIncomingStream;
import claire.util.memory.buffer.ByteArrayOutgoingStream;

final class PersistTest {
	
	public static final int runTest() 
	{
		Log.info.println();
		Log.info.println("----------------------------------");
		Log.info.println("Testing key persistance.");
		int fails = 0;
		for(int i = 0; i < Test.keys.length; i++) {
			ISecret<?> sec = Test.keys[i];
			try {
				Log.info.println("Testing " + sec.getClass().getSimpleName());
				Factory<? extends ISecret<?>> factory = sec.factory();
				
				/*
				 * Raw bytes
				 */
				byte[] bytes = sec.export();
				
				try {
					ISecret<?> cmp = factory.resurrect(bytes);
					Log.warn.println("We got this far");
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
					ISecret<?> cmp = factory.resurrect(bytes, 20);
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
						ISecret<?> cmp = factory.resurrect(is);
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
		}
		return fails;
	}
	
	

}
