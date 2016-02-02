package com.choweiyuan;

import java.io.*;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Main {

  public static void main(String[] args) throws Exception {
    File file = FileUtils.getFile("src/main/resources", "SecretKeyRing.asc");
    Security.addProvider(new BouncyCastleProvider());
    signFileDetached(FileUtils.getFile("src/main/resources", "ABc.xml"), file, new File("src/main/resources", "Abc.xml.pgp"), "Password1".toCharArray());
    System.out.println(verifyFileDetached(FileUtils.getFile("src/main/resources", "ABc.xml"), new File("src/main/resources", "Abc.xml.pgp"), FileUtils.getFile("src/main/resources", "PublicKeyRing.asc")));
  }

  /**
   * <p>Return the first suitable key for encryption in the key ring
   * collection. For this case we only expect there to be one key
   * available for signing.</p>
   *
   * @param input - the input stream of the key PGP Key Ring
   * @return the first suitable PGP Secret Key found for signing
   */
  @SuppressWarnings("unchecked")
  private static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {
    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new BcKeyFingerprintCalculator());
    Iterator<PGPSecretKeyRing> iter = pgpSec.getKeyRings();
    PGPSecretKey secKey = null;

    while(iter.hasNext() && secKey == null) {
      PGPSecretKeyRing keyRing = iter.next();
      Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();

      while(keyIter.hasNext()) {
        PGPSecretKey key = keyIter.next();
        if(key.isSigningKey()) {
          secKey = key;
          break;
        }
      }
    }

    if(secKey != null) {
      return secKey;
    } else {
      throw new IllegalArgumentException("Can't find signing key in key ring.");
    }
  }

  public static void signFileDetached(File fileToSign, File pgpKeyRingFile, File outputFile, char[] passphrase) throws IOException, PGPException, SignatureException {
    InputStream keyInputStream = new BufferedInputStream(new FileInputStream(pgpKeyRingFile));

    OutputStream  outputStream = new ArmoredOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile)));


    PGPSecretKey pgpSecretKey = readSecretKey(keyInputStream);
    PGPPrivateKey pgpPrivateKey = pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
    PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(pgpSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA512).setProvider("BC"));
    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivateKey);

    BCPGOutputStream bOut = new BCPGOutputStream(outputStream);
    InputStream fIn = new BufferedInputStream(new FileInputStream(fileToSign));

    int ch;
    while((ch = fIn.read()) >= 0) {
      signatureGenerator.update((byte)ch);
    }

    fIn.close();

    signatureGenerator.generate().encode(bOut);

    outputStream.close();
    keyInputStream.close();
  }

  public static boolean verifyFileDetached(File fileToVerify, File signatureFile, File publicKeyFile) throws IOException, PGPException, SignatureException {
    InputStream keyInputStream = new BufferedInputStream(new FileInputStream(publicKeyFile));
    InputStream sigInputStream = PGPUtil.getDecoderStream(new BufferedInputStream(new FileInputStream(signatureFile)));

    PGPObjectFactory pgpObjFactory = new PGPObjectFactory(sigInputStream, new BcKeyFingerprintCalculator());

    PGPSignatureList pgpSigList = (PGPSignatureList) pgpObjFactory.nextObject();


    PGPPublicKeyRingCollection pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new BcKeyFingerprintCalculator());
    InputStream fileInputStream = new BufferedInputStream(new FileInputStream(fileToVerify));
    PGPSignature sig = pgpSigList.get(0);
    PGPPublicKey pubKey = pgpPubRingCollection.getPublicKey(sig.getKeyID());
    sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);

    int ch;
    while((ch = fileInputStream.read()) >= 0) {
      sig.update((byte)ch);
    }

    fileInputStream.close();
    keyInputStream.close();
    sigInputStream.close();

    return sig.verify();
  }
}
