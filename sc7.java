import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class sc7 {
    public static KeyPair getKeyPair(String [] storev)
         {
            
         Scanner sc = new Scanner(System.in);
         
         char[] storePass = storev[0].toCharArray();
         
         String fileName = storev[1];
         
         String alias = storev[2];
         
         KeyStore.ProtectionParameter entryPass;
         
         if(storev.length > 3) {
         entryPass=new KeyStore.PasswordProtection(storev[3].toCharArray());
         } else {
             entryPass = null;
         }
         try{
         
            KeyStore store = KeyStore.getInstance("PKCS12");
         
         InputStream input = new FileInputStream(fileName);
         
         store.load(input, storePass);
 
         KeyStore.Entry entry = store.getEntry(alias, entryPass);
         //System.out.println(entry);
         KeyStore keystore = KeyStore.getInstance("PKCS12");
         
         keystore =store;
         
         Key key = keystore.getKey(alias, storePass);
         
         KeyPair pair=null;
         
         if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);
            
            // Get public key
            PublicKey publicKey = cert.getPublicKey();
            
            // Return a key pair
            pair = new KeyPair(publicKey, (PrivateKey) key);
            //System.out.println(pair.getPrivate());
            return pair;
         }
         
                 }
                 catch(Exception e)
                 {
                    System.out.println("Exception : "+ e);
                    return null;
                 }
                 return null;
         }

         public static byte[] getsign(KeyPair pair,PrivateKey privKey,PublicKey pubkey,String msg)
         {   try{   
             Scanner sc = new Scanner(System.in);
            //Creating a Signature object
            Signature sign = Signature.getInstance("SHA256withRSA");
            
            
            //Initialize the signature
            sign.initSign(privKey);
            byte[] bytes = msg.getBytes();
            
            //Adding data to the signature
            sign.update(bytes);
            
            //Calculating the signature
            byte[] signature = sign.sign();
            
            //Printing the signature
            //System.out.println("Digital signature for given text: "+new String(signature, "UTF8"));

            String datatext = Base64.getEncoder().encodeToString(signature);
            System.out.println("OUTPUT:"+datatext);

            //Initializing the signature
            sign.initVerify(pair.getPublic());//this line need to be removed
            sign.update(bytes);
            boolean bool = sign.verify(signature);
      
            if(bool) {
            System.out.println("Signature verified when creating");   
            } else {
            System.out.println("Signature failed when creating");
            }

            return signature;
         }
         catch(Exception e)
            {
                System.out.println("Exception : "+ e);
                return null;
            }
            //return null;
         
        }

        public static PublicKey pkey(FileInputStream fin)
        {PublicKey pukey=null;
         try {
            //CertificateFactory f = CertificateFactory.getInstance("X.509");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate certificate = cf.generateCertificate(fin);
            PublicKey pk = certificate.getPublicKey();
            //System.out.println("cert "+ pk);
            return pukey;
            
         } catch (Exception e) {
            System.out.println(e);
            return pukey;
         }
      }
      
      public  static void ehqw()
      {
      try {  
         // Create f1 object of the file to read data  
         File f1 = new File("D:FileOperationExample.txt");    
         Scanner dataReader = new Scanner(f1);  
         while (dataReader.hasNextLine()) {  
             String fileData = dataReader.nextLine();  
             System.out.println(fileData);  
         }  
         dataReader.close();  
     } catch (FileNotFoundException exception) {  
         System.out.println("Unexcpected error occurred!");  
         exception.printStackTrace();  
     }  
 } 
      public static byte[] cipheren(String msg,PublicKey pubkey)
      {byte[] cipherText=null;
         try {
               
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubkey);
            
            //Adding data to the cipher
            byte[] input = msg.getBytes();
            	  
            cipher.update(input);
  
            //encrypting the data
            cipherText = cipher.doFinal();
            String encryptedText = Base64.getEncoder().encodeToString(cipherText);
            System.out.println("OUTPUT:"+encryptedText);
            //System.out.println("OUTPUT:"+new String(cipherText, "UTF8"));
            /*
            //Initializing the same cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, privkey);
            
            //Decrypting the text
            byte[] decipheredText = cipher.doFinal(cipherText);
            System.out.println(new String(decipheredText));
            */
         } catch (Exception e) {
            System.out.println(e);
         }
         return cipherText; 
      }
      
      
      public static byte [] cipherden(byte [] cipherText,PrivateKey privkey)
      {  
         byte[] decipheredText=null;
         
         try {
               
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         
            //Initializing the same cipher for decryption
            cipher.init(Cipher.DECRYPT_MODE, privkey);
   
            //Decrypting the text
             decipheredText = cipher.doFinal(cipherText);
            System.out.println("OUTPUT"+new String(decipheredText));
         } catch (Exception e) {
            System.out.println(e);
         }
         return decipheredText;
      }

      
      public static void main(String args[]) throws Exception {
         
         
         Scanner sc = new Scanner(System.in);
         //Scanner st = new Scanner("text.txt");
         
         String[] storev=new String[4];
         
         FileReader in = null;
         FileWriter out = null;
         
         File fileObj = new File("./text.txt");
         
         
         
         //creating object of FileWriter class to write things on file
         FileWriter fwObj = new FileWriter("./text.txt");
         
         
         try {
            in = new FileReader("./text.txt");
            out = new FileWriter("./text.txt");
         }
         catch (Exception e)
         {
            System.out.println(e);
         }
         
         
         
         System.out.println("Enter your alias");
         storev[2] = sc.next();

         storev[1]="PRR";

         System.out.println("Enter password");

         storev[0] = sc.next();

         storev[3]=storev[0];

         KeyPair pair=null;

         pair = (KeyPair) getKeyPair(storev);
         //System.out.println(pair.getPrivate());
         
         
         for (int i = 0; i < 1; i++) {
            
            System.out.println("Enter some text");
            sc.nextLine();
            String msg =" hey!"; 
            msg=sc.nextLine();
            
            
            PrivateKey privKey = pair.getPrivate();
            PublicKey  pubkey=pair.getPublic();

            byte [] signature =  getsign(pair,privKey,pubkey,msg);
            
            byte [] ciphertext= cipheren(msg,pubkey);  
            
            byte [] deciphertext=cipherden(ciphertext,privKey);
            //System.out.println("Is file writeable?: " + fileObj.canWrite());
            
            fwObj.write(new String(signature, "UTF8"));
            out.write("Digital signature for given text: ");
            FileInputStream finrb = new FileInputStream("./Raghav.cer");
            FileInputStream finrs = new FileInputStream("./Rana.cer");
            FileInputStream finps = new FileInputStream("./Prabhash.cer");
            PublicKey pubkeyrb=pkey(finrb);
            PublicKey pubkeyrp=pkey(finrs);
            PublicKey pubkeyps=pkey(finps);
            
                   
         }
         out.close();
         fwObj.close();
        
      }

}

