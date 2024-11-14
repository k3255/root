package com.raonsecure.odi.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.Cipher;

import com.raonsecure.odi.crypto.ecies.CryptoKeyHelper;
import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.enums.CurveParamEnum;
import com.raonsecure.odi.crypto.exception.CryptoErrorCode;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.crypto.key.data.IWKeyPairInterface;

public class CryptoManager {

	/**
	 * 키 쌍 생성 - 자바 키 타입으로 생성
	 * @param CurveParamEnum, 	   	타원곡선 알고리즘
	 * @return IWKeyPairInterface, 	keyPair 인터페이스 
	 * @throws CryptoException 
	 */
	public IWKeyPairInterface createRandomKeyPair(CurveParamEnum curveParam) throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		return cryptoKeyHelper.createRandomKeyPair(curveParam);
	}
	
	/**
	 * 키 쌍 생성 - EOS 타입으로 생성
	 * @param CurveParamEnum, 	   	타원곡선 알고리즘
	 * @return IWKeyPairInterface, 	keyPair 인터페이스 
	 * @throws CryptoException 
	 */
	public IWKeyPairInterface createRandomKeyPairInEosKey(CurveParamEnum curveParam) throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		return cryptoKeyHelper.createRandomKeyPairInEosKey(curveParam);
	}

	/**
	 * 키 형태 변환 Java Key를 EOS Type 변환
	 * @param ECPrivatekey, 		자바 키 타입의 개인키
	 * @return EosPrivateKey,		기존 EOS 타입의 개인키
	 * @throws CryptoException 
	 */
	public EosPrivateKey convertKeytoEosPrivateKey(ECPrivateKey priKey) throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		EosPrivateKey convertKey = cryptoKeyHelper.convertKeytoEosPrivateKey(priKey);

		return convertKey;
	}
	
	/**
	 * 키 형태 변환 Java Key를 EOS Type 변환
	 * @param ECPublicKey,			자바 키 타입의 공개키
	 * @return EosPublicKey,		기존 EOS 타입의 개인키
	 * @throws CryptoException 
	 */
	public EosPublicKey convertKeytoEosPublicKey(ECPublicKey pubKey) throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		EosPublicKey convertKey = cryptoKeyHelper.convertKeytoEosPublicKey(pubKey);

		return convertKey;
	}

	/**
	 * Shared Secret 생성
	 * @param String,				Base58 인코딩된 자바 키 타입 공개키
	 * @param ECPrivateKey,			자바 키 타입의 개인키
	 * @return String,				Base58 sharedSecret
	 * @throws CryptoException 
	 */
	public byte[] createSharedSecretByJavaKey(String pubKey, ECPrivateKey priKey) throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		byte[] sharedSecret = null;

		try {
			sharedSecret = cryptoKeyHelper.createSharedSecretByJavaKey(pubKey, priKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PRIVATE_KEY);
		}

		return sharedSecret;
	}

	/**
	 * Shared Secret 생성
	 * @param String,				Base58 인코딩된 자바 키 타입 공개키
	 * @param String,				Base58 인코딩된 자바 키 타입 개인키
	 * @return String,				Base58 sharedSecret
	 * @throws CryptoException 
	 * @throws GeneralSecurityException 
	 */
	public byte[] createSharedSecretByString(String pubKey, String priKey) throws CryptoException, GeneralSecurityException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		
		ECPrivateKey ecPriKey = cryptoKeyHelper.getPrivateKey(priKey);
		byte[] sharedSecret = null;

		try {
			sharedSecret = cryptoKeyHelper.createSharedSecretByJavaKey(pubKey, ecPriKey);

		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PRIVATE_KEY);
		}

		return sharedSecret;
	}
	
	/**
	 * Shared Secret 생성
	 * @param String,				Base58 인코딩 된 EOS 키 타입 공개키
	 * @param EosPrivateKey,		EOS 키 타입 개인키
	 * @return String,				Base58 sharedSecret
	 * @throws CryptoException 
	 */
	public byte[] createSharedSecretByEosKey(String pubKey, EosPrivateKey priKey)
			throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		byte[] sharedSecret = null;

		try {
			sharedSecret = cryptoKeyHelper.createSharedSecretByEosKey(pubKey, priKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PRIVATE_KEY);
		}

		return sharedSecret;
	}
	
	/**
	 * Shared Secret 생성
	 * @param String,				Base58 인코딩 된 EOS 키 타입 공개키
	 * @param String,				Base58 인코딩 된 EOS 키 타입 개인키
	 * @param CurveParamEnum,		타원곡선 알고리즘
	 * @return String,				Base58 sharedSecret
	 * @throws CryptoException 
	 */
	public byte[] createSharedSecretByEosString(String pubKey, String priKey, CurveParamEnum curveParam)
			throws CryptoException {

		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		EosPrivateKey eosPriKey = cryptoKeyHelper.getEosPrivateKeyByString(priKey, curveParam);
		byte[] sharedSecret = null;

		try {
			sharedSecret = cryptoKeyHelper.createSharedSecretByEosKey(pubKey, eosPriKey);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PRIVATE_KEY);
		}

		return sharedSecret;
	}

	/**
	 * 암호화 API
	 * @param byte[],					위에서 생성한 sharedSecret 값
	 * @param byte[],					암호화 할 데이터
	 * @param AesType,					AES 타입
	 * @return String,					Base58 암호화 데이터
	 * @throws CryptoException 
	 */
	public byte[] getEncryptBytes(byte[] nonce, byte[] sharedSecret, byte[] source, AESType aesType) throws CryptoException {

		// TODO- nonce 사용한 대칭키 로직 협의 필요 
		if (aesType != AESType.AES128 && aesType != AESType.AES256) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_OUT_OF_RANGE_VALUE);
		}
		
		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		byte[] enc;
		try {
			enc = cryptoKeyHelper.eciesEncDec(nonce, sharedSecret, source, aesType, Cipher.ENCRYPT_MODE);
		} catch (GeneralSecurityException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_ENCRYPT_FAIL, e);
		}

		if (enc == null) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_ENCRYPT_FAIL);
		}

		return enc;
	}

	/**
	 * 복호화 API
	 * @param byte[],					위에서 생성한 sharedSecret 값
	 * @param byte[],					복호화 할 데이터
	 * @param AesType,					AES 타입
	 * @return String,					Base58 복호화 데이터
	 * @throws CryptoException 
	 */
	public byte[] getDecryptBytes(byte[] nonce, byte[] sharedSecret, byte[] encData, AESType aesType) throws CryptoException {
		// TODO - nonce 사용한 대칭키 로직 협의 필요 
		if (aesType != AESType.AES128 && aesType != AESType.AES256) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_OUT_OF_RANGE_VALUE);
		}
		
		CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
		byte[] dec;
		try {
			dec = cryptoKeyHelper.eciesEncDec(nonce, sharedSecret, encData, aesType, Cipher.DECRYPT_MODE);
		} catch (GeneralSecurityException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_DECRYPT_FAIL, e);
		}

		if (dec == null) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_DECRYPT_FAIL);
		}

		return dec;
	}
	
}
