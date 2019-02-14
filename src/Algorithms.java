import java.awt.AlphaComposite;
import java.awt.Color; 
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.geom.Rectangle2D; 
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.File; 
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;
import javax.swing.JOptionPane;


public class Algorithms {
    private static Cipher encryptCipher;
	private static Cipher decryptCipher;
	private static final byte[] iv = { 11, 22, 33, 44, 99, 88, 77, 66 };
        KeyGenerator keyGenerator = null;
        SecretKey secretKey = null;
        Cipher cipher = null;
        private static final String key = "aesEncryptionKey";
        private static final String initVector = "encryptionIntVec";
        byte[] skey = new byte[1000];
        String skeyString;
        static byte[] raw;
        String inputMessage,encryptedData,decryptedMessage;

        void generateSymmetricKey() {
        try {
        Random r = new Random();
        int num = r.nextInt(10000);
        String knum = String.valueOf(num);
        byte[] knumb = knum.getBytes();
        skey=getRawKey(knumb);
        skeyString = new String(skey);
        System.out.println("Blowfish Symmetric key = "+skeyString);
        }
        catch(Exception e) {
        System.out.println(e);
        }
        }
        private static byte[] getRawKey(byte[] seed) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance("Blowfish");
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(seed);
        kgen.init(128, sr); // 128, 256 and 448 bits may not be available
        SecretKey skey = kgen.generateKey();
        raw = skey.getEncoded();
        return raw;
        }
        private static byte[] encryptBlowFish(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
        }

        private static byte[] decryptBlowFish(byte[] raw, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
        }
            
        private void encryptImage(String srcPath, String destPath) throws InvalidKeyException, BadPaddingException {
            File rawFile = new File(srcPath);
            File encryptedFile = new File(destPath);
            InputStream inStream = null;
            OutputStream outStream = null;
            try {
                /**
                 * Initialize the cipher for encryption
                 */
                //cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                /**
                 * Initialize input and output streams
                 */
                inStream = new FileInputStream(rawFile);
                outStream = new FileOutputStream(encryptedFile);
                byte[] buffer = new byte[1024];
                int len;
                while ((len = inStream.read(buffer)) > 0) {
                    outStream.write(cipher.update(buffer, 0, len));
                    outStream.flush();
                }
                outStream.write(cipher.doFinal());
                inStream.close();
                outStream.close();
            } catch (IllegalBlockSizeException ex) {
                System.out.println(ex);
            } catch (BadPaddingException ex) {
                System.out.println(ex);
            } catch (FileNotFoundException ex) {
                System.out.println(ex);
            } catch (IOException ex) {
                System.out.println(ex);
        }
    }
        private void decryptImage(String srcPath, String destPath) {
        File encryptedFile = new File(srcPath);
        File decryptedFile = new File(destPath);
        InputStream inStream = null;
        OutputStream outStream = null;
        try {
            /**
             * Initialize the cipher for decryption
             */
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            /**
             * Initialize input and output streams
             */
            inStream = new FileInputStream(encryptedFile);
            outStream = new FileOutputStream(decryptedFile);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = inStream.read(buffer)) > 0) {
                outStream.write(cipher.update(buffer, 0, len));
                outStream.flush();
            }
            outStream.write(cipher.doFinal());
            inStream.close();
            outStream.close();
        } catch (IllegalBlockSizeException ex) {
            System.out.println(ex);
        } catch (BadPaddingException ex) {
            System.out.println(ex);
        } catch (InvalidKeyException ex) {
            System.out.println(ex);
        } catch (FileNotFoundException ex) {
            System.out.println(ex);
        } catch (IOException ex) {
            System.out.println(ex);
        }
    }

	static int gcd(int e, int z)
	{
		if(e==0)
			return z;	
		else
			return gcd(z%e,e);
	}
	public static void RSA() {
		Scanner sc=new Scanner(System.in);
		int p,q,n,z,d=0,e,i;
		System.out.println("Enter the number to be encrypted and decrypted");
		int msg=sc.nextInt();
		double c;
		BigInteger msgback; 
		System.out.println("Enter 1st prime number p");
		p=sc.nextInt();
		System.out.println("Enter 2nd prime number q");
		q=sc.nextInt();
		
		n=p*q;
		z=(p-1)*(q-1);
		System.out.println("the value of z = "+z);		

		for(e=2;e<z;e++)
		{
			if(gcd(e,z)==1)            // e is for public key exponent
			{				
				break;
			}
		}
		System.out.println("the value of e = "+e);				
		for(i=0;i<=9;i++)
		{
			int x=1+(i*z);
			if(x%e==0)      //d is for private key exponent
			{
				d=x/e;
				break;
			}
		}
		System.out.println("the value of d = "+d);		
		c=(Math.pow(msg,e))%n;
		System.out.println("Encrypted message is : -");
		System.out.println(c);
                //converting int value of n to BigInteger
		BigInteger N = BigInteger.valueOf(n);
		//converting float value of c to BigInteger
		BigInteger C = BigDecimal.valueOf(c).toBigInteger();
		msgback = (C.pow(d)).mod(N);
		System.out.println("Derypted message is : -");
		System.out.println(msgback);
	}
	public static String getMd5(String input) 
    { 
        try { 
  
            // Static getInstance method is called with hashing MD5 
            MessageDigest md = MessageDigest.getInstance("MD5"); 
  
            // digest() method is called to calculate message digest 
            //  of an input digest() return array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
            return hashtext; 
        }  
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    }
	static void addTextWatermark(String text, File sourceImageFile, File destImageFile) {
		try { 
			BufferedImage sourceImage = ImageIO.read(sourceImageFile);
			Graphics2D g2d = (Graphics2D) sourceImage.getGraphics();
			// initializes necessary graphic properties
			AlphaComposite alphaChannel = AlphaComposite.getInstance( AlphaComposite.SRC_OVER, 0.3f);
			g2d.setComposite(alphaChannel); g2d.setColor(Color.RED); 
			g2d.setFont(new Font("Arial", Font.BOLD, 64)); 
			FontMetrics fontMetrics = g2d.getFontMetrics(); 
			Rectangle2D rect = fontMetrics.getStringBounds(text, g2d); 
			// calculates the coordinate where the String is painted 
			int centerX = (sourceImage.getWidth() - (int) rect.getWidth()) / 2; 
			int centerY = sourceImage.getHeight() / 2; // paints the textual watermark 
			g2d.drawString(text, centerX, centerY); 
			ImageIO.write(sourceImage, "png", destImageFile); 
			g2d.dispose(); 
			System.out.println("The tex watermark is added to the image."); 
		}
		catch (IOException ex) 
		{ 
			System.err.println(ex); 
		}
		}
		static void addImageWatermark(File watermarkImageFile, File sourceImageFile, File destImageFile) {
			try { 
				BufferedImage sourceImage = ImageIO.read(sourceImageFile); 
				BufferedImage watermarkImage = ImageIO.read(watermarkImageFile); 
				// initializes necessary graphic properties 
				Graphics2D g2d = (Graphics2D) sourceImage.getGraphics(); 
				AlphaComposite alphaChannel = AlphaComposite.getInstance( AlphaComposite.SRC_OVER, 0.3f); 
				g2d.setComposite(alphaChannel); // calculates the coordinate where the image is painted 
				int topLeftX = (sourceImage.getWidth() - watermarkImage.getWidth()) / 2; 
				int topLeftY = (sourceImage.getHeight() - watermarkImage .getHeight()) / 2; 
				// paints the image watermark 
				g2d.drawImage(watermarkImage, topLeftX, topLeftY, null); 
				ImageIO.write(sourceImage, "png", destImageFile); g2d.dispose(); 
				System.out.println("The image watermark is added to the image."); 
				} 
			catch (IOException ex) 
			{ System.err.println(ex); } 
			} 
        /*public static String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
        
	public static String decrypt(String encrypted) {
            try {
                IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
                SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
                byte[] original;
                original = cipher.doFinal(Base64.decodeBase64(encrypted));

                return new String(original);
            } catch (Exception ex) {
                ex.printStackTrace();
            }

            return null;
        }*/

	public void running() throws InvalidKeyException, BadPaddingException, IOException {
		System.out.println();
		while(true) {
			int ch = 0;
                        System.out.println("1. RSA\n 2. MD5\n 3. Watermaking \n 4. Image Encryption\n 5. Audio Encryption\n 6.AES \n 7.Blowfish \n 8.DES");
                        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in)); 
         
                    // Reading data using readLine 
                    String name = reader.readLine();
                    ch = Integer.parseInt(name);
			
			switch(ch) {
                            case 1:{
                                RSA();
                            }
                            break;
                            case 2:{
                                String input = "Hello";
                                System.out.println(" MD5 code of " +input+ " is "+getMd5(input));
                            }
                            break;
                            case 3:{
                                    File sourceImageFile = new File("C:\\Users\\205117057\\Desktop\\website.jpg"); 
                                    File destImageFile = new File("C:\\Users\\205117057\\Desktop\\text_watermarked.png"); 
                                    addTextWatermark("Mrbool", sourceImageFile, destImageFile); 
                                    destImageFile = new File("C:\\Users\\205117057\\Desktop\\123.jpg"); 
                                    File watermarkImageFile = new File("C:\\Users\\205117057\\Desktop\\moon.jpg"); 
                                    addImageWatermark(watermarkImageFile, sourceImageFile, destImageFile); 
                            }
                            break;
                            case 4:{
                                String fileToEncrypt = "moon.jpg";
                                String encryptedFile = "website.jpg";
                                String decryptedFile = "text_watermarked.png";
                                String directoryPath = "C:\\Users\\205117057\\Desktop\\";
                                //EncryptFile encryptFile = new EncryptFile();
                                System.out.println("Starting Encryption...");
                                encryptImage("C:\\Users\\205117057\\Desktop\\moon.jpg",
                                        "C:\\Users\\205117057\\Desktop\\moon.jpg\\website.jpg");
                                System.out.println("Encryption completed...");
                                System.out.println("Starting Decryption...");
                                decryptImage(directoryPath + encryptedFile,
                                        directoryPath + decryptedFile);
                                System.out.println("Decryption completed...");
                            }
                            break;
                            case 6:{/*
                                String originalString = "password";
                                System.out.println("Original String to encrypt - " + originalString);
                                String encryptedString = encrypt(originalString);
                                System.out.println("Encrypted String - " + encryptedString);
                                String decryptedString = decrypt(encryptedString);
                                System.out.println("After decryption - " + decryptedString);*/
                            }
                            break;
                            case 7:
                            {/*
                                try {
                                    generateSymmetricKey();

                                    inputMessage=JOptionPane.showInputDialog(null,"Enter message to encrypt");
                                    byte[] ibyte = inputMessage.getBytes();
                                    byte[] ebyte=encryptBlowFish(raw, ibyte);
                                    String encryptedData = new String(ebyte);
                                    System.out.println("Encrypted message "+encryptedData);
                                    JOptionPane.showMessageDialog(null,"Encrypted Data "+"\n"+encryptedData);

                                    byte[] dbyte= decryptBlowFish(raw,ebyte);
                                    String decryptedMessage = new String(dbyte);
                                    System.out.println("Decrypted message "+decryptedMessage);

                                    JOptionPane.showMessageDialog(null,"Decrypted Data "+"\n"+decryptedMessage);
                                    }
                                    catch(Exception e) {
                                    System.out.println(e);
                                    }*/
                            }
                            break;
                            case 8:
                            {/*
                                

                                String clearTextFile = "C:\\Users\\205117057\\Desktop\\123.txt";
                        String cipherTextFile = "C:\\Users\\205117057\\Desktop\\234.txt";
                        String clearTextNewFile = "C:\\Users\\205117057\\Desktop\\3.txt";

                        try {
                                // create SecretKey using KeyGenerator
                                SecretKey key = KeyGenerator.getInstance("DES").generateKey();
                                AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);

                                // get Cipher instance and initiate in encrypt mode
                                encryptCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                                encryptCipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

                                // get Cipher instance and initiate in decrypt mode
                                decryptCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                                decryptCipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

                                // method to encrypt clear text file to encrypted file
                                encrypt(new FileInputStream(clearTextFile), new FileOutputStream(cipherTextFile));

                                // method to decrypt encrypted file to clear text file
                                decrypt(new FileInputStream(cipherTextFile), new FileOutputStream(clearTextNewFile));
                                System.out.println("DONE");
                        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                                        | InvalidAlgorithmParameterException | IOException e) {
                                e.printStackTrace();
		}*/
                            }
		}
	}
	}
        public static void main(String[] args) throws IOException, InvalidKeyException, BadPaddingException  
    { 
        Algorithms a = new Algorithms();
        a.running();
    } 
}
