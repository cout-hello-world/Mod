import java.math.BigInteger;
import java.io.*;
public class Mod {
	public static void main(String args[]) {
		BigInteger modulus = M37;
		if (args[0].equals("--get-modulus")) {
			System.out.printf("%d%n", modulus);
		} else if (args[0].equals("--gen-key")) {
			BigInteger key = computeKeyVal(args[1]);
			if (key != null) {
				saveValue(args[2], key);
			} else { // These lines will probably never execute.
				System.err.println("Key generation failed.");
				System.err.println("Delete that " + MOD_SIZE + " byte random file and try with a new one");
			}
		} else if (args[0].equals("--encrypt") || args[0].equals("-e")) {
			BigInteger plainText = getValue(args[1]);
			BigInteger encryptionKey = getValue(args[2]);
			BigInteger cipherText = encryptionKey.add(plainText).mod(modulus); 
			saveValue(args[3], cipherText);
		} else if (args[0].equals("--mac") || args[0].equals("-m")) {
			BigInteger plainText = getValue(args[1]);
			BigInteger authenticationKey = getValue(args[2]);
			BigInteger mac = authenticationKey.multiply(plainText).mod(modulus);
			saveValue(args[3], mac);
		} else if (args[0].equals("--decrypt") || args[0].equals("-d")) {
			BigInteger cipherText = getValue(args[1]);
			BigInteger encryptionKey = getValue(args[2]);
			BigInteger plainText = cipherText.subtract(encryptionKey).mod(modulus); 
			saveValue(args[3], plainText);
		} else if (args[0].equals("--verify") || args[0].equals("-v")) {
			BigInteger plainText = getValue(args[1]);
			BigInteger authenticationKey = getValue(args[2]);
			BigInteger mac = getValue(args[3]);
			BigInteger shouldEqualMac = plainText.multiply(authenticationKey).mod(modulus);
			if (shouldEqualMac.equals(mac)) {
				System.out.println("Your plain text checks out.");
			} else {
				System.out.println("Mallory has tampered with your data!");
				System.out.println("Do not trust the message.");
				System.out.println("The mac of the plain text does not match the input mac.");
			}
		}
	}
	private static BigInteger computeKeyVal(String fileName) {
		BigInteger a = readIn(fileName, true);
		if (a.compareTo(M37) < 0) {
			return a;
		} else {
			return null;
		}
	}
	private static BigInteger getValue(String fileName) {
		return readIn(fileName, false);
	}
	private static BigInteger readIn(String fileName, boolean keyGenMode) {
		File input = new File(fileName);
		int size = (int)input.length();
		if (keyGenMode && size != MOD_SIZE) throw new RuntimeException("The size of the input must be " + MOD_SIZE + " bytes.");
		BigInteger n = null;
		try (FileInputStream inputStream = new FileInputStream(fileName)) {
			n = BigInteger.ZERO;
			for (int i = size - 1; i >= 0; i--) {
				if (keyGenMode) {
					n = n.add(TWO.pow(8 * i).multiply(new BigInteger(Integer.toString(inputStream.read() & 0x1))));
					keyGenMode = false;
					continue;
				}
				n = n.add(TWO.pow(8 * i).multiply(new BigInteger(Integer.toString(inputStream.read()))));
			}
		} catch (IOException ex) {
			ex.printStackTrace();
			System.exit(1);
		}
		return n;
	}
	private static void saveValue(String fileName, BigInteger n) {
		try (FileOutputStream outputStream = new FileOutputStream(fileName)) {
			outputStream.write(n.toByteArray());
		} catch (IOException ex) {
			ex.printStackTrace();
			System.exit(1);
		}
	}
	private static BigInteger mersenne(int p) {
		return TWO.pow(p).subtract(BigInteger.ONE);
	}
	private static final BigInteger TWO = new BigInteger("2");
	private static final BigInteger M37 = mersenne(3021377);
	private static final int MOD_SIZE = 377673;
}
