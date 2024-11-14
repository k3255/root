package com.raonsecure.odi.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.raonsecure.odi.crypto.ecies.CryptoHelper;
import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.enums.CurveParamEnum;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.crypto.key.data.IWKeyPairInterface;
import com.raonsecure.odi.crypto.util.MultiBase;

public class CryptoSample {
	
	private CurveParamEnum keyType = CurveParamEnum.SECP256_R1;
	CryptoManager cryptoManager = new CryptoManager();
	CryptoHelper cryptoHelper = new CryptoHelper();

	@DisplayName("enc/dec with sharedsecret")
	@Test
	void cryptoTest() throws CryptoException {
		
		IWKeyPairInterface keyPair = cryptoManager.createRandomKeyPairInEosKey(keyType);
		IWKeyPairInterface keyPair2 = cryptoManager.createRandomKeyPairInEosKey(keyType);
		System.out.println("1. create shared secert");
//		byte[] pubKey1 = ((EosPublicKey)keyPair.getPubKey()).getBytes();
//		String encodePubKey1 = MultiBase.encode(pubKey1, MultiBaseEnum.Base58btc);
		

		String encodePubKey1 = keyPair.getBase58PubKey();
		
		byte[] priKey1 = ((EosPrivateKey)keyPair.getPriKey()).getBytes();
		String encodePriKey1 = MultiBase.encode(priKey1, MultiBaseEnum.Base58btc);
		
//		byte[] pubKey2 = ((EosPublicKey)keyPair2.getPubKey()).getBytes();
//		String encodePubKey2 = MultiBase.encode(pubKey2, MultiBaseEnum.Base58btc);
		String encodePubKey2 = keyPair2.getBase58PubKey();
		
		
		byte[] priKey2 = ((EosPrivateKey)keyPair2.getPriKey()).getBytes();
		String encodePriKey2 = MultiBase.encode(priKey2, MultiBaseEnum.Base58btc);
		System.out.println("encodePriKey1 : " + encodePriKey1 + " / length : " + MultiBase.decode(encodePriKey1).length);
		System.out.println("encodePubKey1 : " + encodePubKey1 + " / length : " + MultiBase.decode(encodePubKey1).length);
		System.out.println("encodePriKey2 : " + encodePriKey2 + " / length : " + MultiBase.decode(encodePriKey2).length);
		System.out.println("encodePubKey2 : " + encodePubKey2 + " / length : " + MultiBase.decode(encodePubKey2).length);

		encodePriKey2 = "zHahLMU93ai44j1EiC3TJBFveoBMLWsvZeTLr877VVUS1";
		encodePubKey1 = "zejFuggvYMJjBt6PQCxWNyqwg7wnrj8aum4t3Mn5LZh5w";
		byte[] sharedSecret = cryptoManager.createSharedSecretByEosString(encodePubKey2, encodePriKey1, keyType);
		byte[] sharedSecret2 = cryptoManager.createSharedSecretByEosString(encodePubKey1, encodePriKey2, keyType);

		System.out.println("2. Create SharedSecret  ::: " +  MultiBase.encode(sharedSecret, MultiBaseEnum.Base58btc));
		System.out.println("2. Create SharedSecret2  ::: " +  MultiBase.encode(sharedSecret2, MultiBaseEnum.Base58btc));
		//Assertions.assertArrayEquals(sharedSecret, sharedSecret2);
		
		
		
		byte[] nonce = cryptoHelper.generateNonce();
		String palinData = "crypto";
		byte[] encryptedData = cryptoManager.getEncryptBytes(nonce, sharedSecret, palinData.getBytes(), AESType.AES256);
		System.out.println("3. Encrypt whih SharedSecret.");
	
		byte[] decryptedData = cryptoManager.getDecryptBytes(nonce, sharedSecret2, encryptedData, AESType.AES256);
		System.out.println("4. Decrypt whih SharedSecret.");
		assertEquals(palinData, new String(decryptedData));	
	}
	
	@DisplayName("convert eckey to eos key")
	@Test
	void convertTest() throws CryptoException {
		IWKeyPairInterface keyPair = cryptoManager.createRandomKeyPair(keyType);
		
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPubKey();
		ECPrivateKey privateKey = (ECPrivateKey)keyPair.getPriKey();
		
		cryptoManager.convertKeytoEosPrivateKey(privateKey);		
		cryptoManager.convertKeytoEosPublicKey(publicKey);
			
	}
}
