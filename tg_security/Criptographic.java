package tg_security;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.util.Store;


public class Criptographic {
    
    Criptographic() {}
    
    public byte[] signature (byte[] data, List file) throws IOException, OperatorCreationException, CertificateEncodingException, CMSException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, KeyStoreException, CertificateException, UnrecoverableKeyException{
        
        byte[] message;

        List certList = new ArrayList();
        
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        CMSTypedData cmsData= new CMSProcessableByteArray(data);
        
        for (int i = 0; i < file.size(); i++){
            String p12 = file.get(i).toString();
            char[] key = this.getPassword();
                                
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream(p12), key);
            String alias = (String) keystore.aliases().nextElement();
            PrivateKey private_key = (PrivateKey) keystore.getKey(alias, key);
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
            
            certList.add(certificate);
        
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(private_key);
            cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                 new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build()).build(contentSigner, certificate));
        }    

        Store certs = new JcaCertStore(certList);
    	
        cmsGenerator.addCertificates(certs);
        
        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        message = cms.getEncoded();
        
        return message;
    }
    
    public boolean verification (byte[] data) throws CertificateException, OperatorCreationException, CMSException {
        
        try {
            //boolean resp = false;
            
            CMSSignedData signedData = new CMSSignedData(data); //inclui o Signer 
            
            Store store = signedData.getCertificates();
            
            SignerInformationStore signers = signedData.getSignerInfos(); // informações das pessoas que assinaram o documento
            Collection c = signers.getSigners(); //coleção com todos os assinantes
            Iterator it = c.iterator();

            while (it.hasNext()){
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = store.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                X509Certificate certFromSignedData = new JcaX509CertificateConverter().
                        setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certHolder);
                if(!signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(certFromSignedData)))
                    return false;
            }
            return true;
        } catch (CMSException ex) {
            //System.out.println("org.bouncycastle.cms.CMSException: Malformed content.");
            //Logger.getLogger(Criptographic.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        } 
    }
    
    public char [] getPassword() {
        Scanner scanner = new Scanner (System.in);
        String senha = "ls";
        boolean boll = true;
        while (boll){
            System.out.println("Digite sua senha");
            senha = scanner.nextLine();
            boll = false;
        }
        
        char[] keyPassword = senha.toCharArray();
        return keyPassword;
    }
}
