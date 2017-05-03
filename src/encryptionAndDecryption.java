import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

public class encryptionAndDecryption {
	private SecretKeySpec secretKey;
	private Cipher cipher;
	byte[] encryptedText = null;
	
	public encryptionAndDecryption(String secret, int length, String algorithm)
			throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] key = new byte[length];
		key = fixSecret(secret, length);
		this.secretKey = new SecretKeySpec(key, algorithm);
		this.cipher = Cipher.getInstance(algorithm);
	}
	
	static String readFile(String path, Charset encoding) 
			  throws IOException 
			{
			  byte[] encoded = Files.readAllBytes(Paths.get(path));
			  return new String(encoded, encoding);
			}

	private byte[] fixSecret(String s, int length) throws UnsupportedEncodingException {
		if (s.length() < length) {
			int missingLength = length - s.length();
			for (int i = 0; i < missingLength; i++) {
				s += " ";
			}
		}
		return s.substring(0, length).getBytes("UTF-8");
	}
	public byte[] encryptText( String key, String plainText )
			throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {	
		this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
		return null;
		
	}

	public String decryptText(String key, byte[] encruptedText)
			throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
		return null;
		
	}
	
	public static void main (String[] args) throws IOException{
		String xmlString = readFile("src/cryptodir/simpleFile.xml", StandardCharsets.UTF_8);
		File dir = new File("src/cryptodir");
		File[] filelist = dir.listFiles();
		
		encryptionAndDecryption ske;
		try {
			ske = new encryptionAndDecryption("!@#$MySecr3tPassw0rd", 16, "AES");
			//ske = new SymmetricKeyExample("!@#$MySecr3tPassw0rd", 16, "Blowfish");

			int choice = -2;
			while (choice != -1) {
				String[] options = { "Encrypt", "Decrypt", "Exit" };
				choice = JOptionPane.showOptionDialog(null, "Select an option", "Options", 0,
						JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

				switch (choice) {
				case 0:
					
						try {
							ske.encryptText("!@#$MySecr3tPassw0rd", xmlString);
							
						} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
								| IOException e) {
							System.err.println("Couldn't encrypt : "  + e.getMessage());
						}
					
					System.out.println("Files encrypted successfully");
					break;
				case 1:
					
						try {
							ske.decryptFile("!@#$MySecr3tPassw0rd",encryptedText);
						} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
								| IOException e) {
							System.err.println("Couldn't decrypt: " + e.getMessage());
						}
					
					System.out.println("Files decrypted successfully");
					break;
				default:
					choice = -1;
					break;
				}
			}
		} catch (UnsupportedEncodingException ex) {
			System.err.println("Couldn't create key: " + ex.getMessage());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.err.println(e.getMessage());
		}
	}
}