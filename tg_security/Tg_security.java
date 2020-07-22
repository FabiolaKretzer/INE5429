package tg_security;

import java.io.*;
import java.util.Scanner;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CryptoException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class Tg_security {

    public static void main(String[] args) throws KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException, CMSException, OperatorCreationException, CertificateEncodingException, InvalidKeyException, SignatureException, NoSuchProviderException, CryptoException {
        Security.addProvider(new BouncyCastleProvider());
        
        FileInputStream crunchifyInputStream = null;
        
		File crunchifyFile = new File("/home/100000000819936/NetBeansProjects/TG/src/tg/data.txt");
 
		byte[] data = new byte[(int) crunchifyFile.length()];
 
		try {
 
			crunchifyInputStream = new FileInputStream(crunchifyFile);
			crunchifyInputStream.read(data);
			crunchifyInputStream.close();
 
		} catch (Exception e) {
		}
       
        
        String file1 = "C:\\Users\\GQS\\Documents\\NetBeansProjects\\tg_security\\src\\tg_security\\Baeldung.p12";
        String file2 = "C:\\Users\\GQS\\Documents\\NetBeansProjects\\tg_security\\src\\tg_security\\TGCertificate.p12";
        
        List pList = new ArrayList();
        pList.add(file1);
        pList.add(file2);
        
        Criptographic crip = new Criptographic();
        
        byte[] signature = crip.signature(data, pList);
        
        FileOutputStream fileOuputStream = null;

        try {
            fileOuputStream = new FileOutputStream("C:\\Users\\GQS\\Documents\\NetBeansProjects\\tg_security\\src\\tg_security\\datasigned.txt");
            fileOuputStream.write(signature);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (fileOuputStream != null) {
                try {
                    fileOuputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        
        boolean verification = crip.verification(signature);
        
        System.out.println(verification);
        
    }
    
}
