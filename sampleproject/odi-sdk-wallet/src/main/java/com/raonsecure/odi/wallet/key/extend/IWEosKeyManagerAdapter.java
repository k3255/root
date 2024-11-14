package com.raonsecure.odi.wallet.key.extend;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import com.raonsecure.odi.crypto.digest.Sha256;
import com.raonsecure.odi.crypto.ec.CurveParam;
import com.raonsecure.odi.crypto.ec.EcTools;
import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.exception.CryptoErrorCode;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.crypto.util.MultiBase;
import com.raonsecure.odi.wallet.eoscommander.crypto.ec.EcDsa;
import com.raonsecure.odi.wallet.eoscommander.crypto.ec.EcSignature;
import com.raonsecure.odi.wallet.exception.IWErrorCode;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.IWKeyManagerImpl;
import com.raonsecure.odi.wallet.key.data.IWKey;
import com.raonsecure.odi.wallet.key.data.IWKeyElement;
import com.raonsecure.odi.wallet.key.data.IWKeyStoreData;
import com.raonsecure.odi.wallet.key.data.IWKey.ALGORITHM_TYPE;
import com.raonsecure.odi.wallet.key.store.IWKeyFile;
import com.raonsecure.odi.wallet.util.GDPLogger;
import com.raonsecure.oid.crypto.encoding.Base58;

public class IWEosKeyManagerAdapter extends IWKeyManagerImpl {

	/**
	 * 서버에서 사용할 키 맵 tykim: 서버쪽 매번 키파일을 로드하지 않도록 수정함
	 */
	public Map<String, EosPrivateKey> privateKeyMap = new HashMap<String, EosPrivateKey>();
	public Map<String, EosPublicKey> publicKeyMap = new HashMap<String, EosPublicKey>();
//	private CryptoManager cryptoManager = new CryptoManager();

	public IWEosKeyManagerAdapter(char[] pwd, AESType aesType) throws IWException {
		super(pwd, aesType);
	}

	public IWEosKeyManagerAdapter(String keyFile_pathWithName) throws IWException {
		super(keyFile_pathWithName);
	}

	public IWEosKeyManagerAdapter(String walletJson, char[] pwd) throws IWException {
		super(walletJson, pwd);
	}

	@Override
	protected IWKey getIWKeyFromIWKeyElement(IWKeyElement iwKeyElement) throws IWException {
		String keyId = iwKeyElement.getKeyId();

		EosPublicKey pubKey = getEosPublicKeyObject(keyId);
		EosPrivateKey priKey = getPrivateKey(keyId);
		IWKey iwKey = new IWKey(keyId, iwKeyElement.getAlg(), pubKey, priKey);
		return iwKey;

	}

	@Override
	protected byte[] getPrivateKeyBytes(IWKey iwKey) {
		byte[] privateBytes = null;
		if (!(iwKey.getAlg() == ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue()
				|| iwKey.getAlg() == ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue())) {
			// 에러 메시지 추가
		}
		privateBytes = iwKey.getEosPriKey().getBytes();
		return privateBytes;
	}

	@Override
	protected byte[] getPublicKeyBytes(IWKey iwKey) {
		byte[] publicKeyBytes = null;
		if (!(iwKey.getAlg() == ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue()
				|| iwKey.getAlg() == ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue())) {
		}
		publicKeyBytes = iwKey.getEosPubKey().getBytes();
		return publicKeyBytes;
	}

	@Override
	protected byte[] getSignBytes(String keyId, byte[] source) throws IWException {
		EosPrivateKey key = getPrivateKey(keyId);
		if (key == null) {
			GDPLogger.debug("ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST - " + keyId);
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST.getCode(), keyId);
		}
		return sign(key, source, false);
	}

	@Override
	protected byte[] getSignBytes(String keyId, byte[] source, boolean bCanonical) throws IWException {
		EosPrivateKey key = getPrivateKey(keyId);
		if (key == null) {
			GDPLogger.debug("ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST - " + keyId);
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST.getCode(), keyId);
		}
		return sign(key, source, bCanonical);
	}

	@Override
	protected byte[] getSignBytesWithHashData(String keyId, byte[] hashedSource, boolean bCanonical)
			throws IWException {
		EosPrivateKey key = getPrivateKey(keyId);
		if (key == null) {
			GDPLogger.debug("ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST - " + keyId);
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST.getCode(), keyId);
		}
		return signWithHashData(key, hashedSource, bCanonical);
	}

	@Override
	protected void verify(byte[] pubkey_rw, byte[] source, byte[] signature, int curveParamType) throws IWException {
		CurveParam curveParam = EcTools.getCurveParam(curveParamType);

		EcSignature ecSignature = new EcSignature(signature, curveParam);

		Sha256 hash = Sha256.from(source);
		byte[] data = hash.getBytes();

		EosPublicKey pubKey = new EosPublicKey(pubkey_rw, ecSignature.curveParam);

		for (int i = 0; i < 4; i++) {
			EosPublicKey recovered = EcDsa.recoverPubKey(curveParam, data, ecSignature, i);
			if (pubKey.equals(recovered)) {
				ecSignature.setRecid(i);
				// success
				return;
			}
		}

		if (ecSignature.recId < 0) {
			throw new IllegalStateException("could not find recid. Was this data signed with this key?");
		}
		throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_VERIFY_SIGN_FAIL);
	}

	@Override
	protected void verifyWithHashData(byte[] pubkey_rw, byte[] hashedSource, byte[] signature, int curveParamType)
			throws IWException {
		CurveParam curveParam = EcTools.getCurveParam(curveParamType);

		EcSignature ecSignature = new EcSignature(signature, curveParam);

		Sha256 hash = new Sha256(hashedSource);
		byte[] data = hash.getBytes();

		EosPublicKey pubKey = new EosPublicKey(pubkey_rw, ecSignature.curveParam);

		for (int i = 0; i < 4; i++) {
			EosPublicKey recovered = EcDsa.recoverPubKey(curveParam, data, ecSignature, i);
			if (pubKey.equals(recovered)) {
				ecSignature.setRecid(i);
				// success
				return;
			}
		}

		if (ecSignature.recId < 0) {
			throw new IllegalStateException("could not find recid. Was this data signed with this key?");
		}
		throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_VERIFY_SIGN_FAIL);

	}

	private byte[] sign(EosPrivateKey key, byte[] source, boolean bCanonical) {
		// ref com.raonsecure.gdp.key.GDPIssueReg
		Sha256 sha256 = Sha256.from(source);
		EcSignature ecSignature = EcDsa.sign(sha256, key, bCanonical);
		byte[] signature = ecSignature.eosEncoding(true);
		return signature;
	}

	private byte[] signWithHashData(EosPrivateKey key, byte[] hashedSource, boolean bCanonical) {
		Sha256 sha256 = new Sha256(hashedSource);
		EcSignature ecSignature = EcDsa.sign(sha256, key, bCanonical);
		byte[] signature = ecSignature.eosEncoding(true);
		return signature;
	}

	private EosPrivateKey getPrivateKey(String keyId) throws IWException {
		if (!isConnect())
			return null;

		/**
		 * 서버에서 사용할 키 맵 tykim: 서버쪽 매번 키파일을 로드하지 않도록 수정함
		 */
		if (IWKeyFile.ONETIME_LOAD) {
			EosPrivateKey privKey = privateKeyMap.get(keyId);
			if (privKey != null) {
				return privKey;
			}
		}

		IWKeyElement key = getIWKey(keyId);
		if (key == null)
			return null;

		byte[] encPrivKey = null;
		try {
			encPrivKey = MultiBase.decode(key.getPrivateKey());
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] decPrivKey = symDecPrivateKey(encPrivKey);
		EosPrivateKey privKey = new EosPrivateKey(ALGORITHM_TYPE.getCurveInt(key.getAlg()), decPrivKey);

		if (IWKeyFile.ONETIME_LOAD) {
			privateKeyMap.put(keyId, privKey);
		}

		return privKey;
	}

	private EosPublicKey getEosPublicKeyObject(String keyId) throws IWException {
		if (!isConnect())
			return null;

		/**
		 * 서버에서 사용할 키 맵 tykim: 서버쪽 매번 키파일을 로드하지 않도록 수정함
		 */
		if (IWKeyFile.ONETIME_LOAD) {
			EosPublicKey pubKey = publicKeyMap.get(keyId);
			if (pubKey != null) {
				return pubKey;
			}
		}

		IWKeyElement key = getIWKey(keyId);
		if (key == null)
			return null;

		byte[] pubKey0;
		try {
			pubKey0 = MultiBase.decode(key.getPublicKey());
			EosPublicKey pubKey = new EosPublicKey(ALGORITHM_TYPE.getCurveInt(key.getAlg()), pubKey0);

			if (IWKeyFile.ONETIME_LOAD) {
				publicKeyMap.put(keyId, pubKey);
			}

			return pubKey;
		} catch (Exception e) {
//			e.printStackTrace();
		}
		return null;
	}

	@Override
	public byte[] getECIESEncryptBytes(String keyId, byte[] nonce, String publicKey, byte[] source, AESType aesType)
			throws IWException, CryptoException {

		if (!isConnect()) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);
		}

		EosPrivateKey eosPrivateKey = getPrivateKey(keyId);

		if (eosPrivateKey == null) {
			GDPLogger.debug("ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST - " + keyId);
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST.getCode(), keyId);
		}

		byte[] encryptData = null;
		byte[] sharedSecret = null;

		try {
		    sharedSecret = innerGetSharedSecret(publicKey, eosPrivateKey);
		    encryptData = cryptoKeyHelper.eciesEncDec(nonce, sharedSecret, source, aesType, Cipher.ENCRYPT_MODE);
		} catch (CryptoException e) {
		    if (sharedSecret == null) {
		        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_GEN_SECRET_FAIL, e);
		    } else {
		        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_ENCRYPT_FAIL, e);
		    }
		} catch (GeneralSecurityException e) {
		    throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_ENCRYPT_FAIL, e);
		}

		return encryptData;
	}

	@Override
	public byte[] getSharedSecret(String keyId, String publicKey) throws IWException {
		if (!isConnect()) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);
		}
		EosPrivateKey eosPrivateKey = getPrivateKey(keyId);

		if (eosPrivateKey == null) {
			GDPLogger.debug("ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST - " + keyId);
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST.getCode(), keyId);
		}

		byte[] sharedSecret = null;
		try {
			sharedSecret =  innerGetSharedSecret(publicKey, eosPrivateKey);
		} catch (CryptoException e) {
			e.printStackTrace();
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_ECIES_GEN_SECRET_FAIL, e);
		}
		return sharedSecret;
	}


	private byte[] innerGetSharedSecret(String publicKey, EosPrivateKey privateKey) throws CryptoException {

//		byte[] sharedSecret = cryptoManager.createSharedSecretByEosKey(publicKey, privateKey);
		byte[] sharedSecret = null;
		try {
			sharedSecret = cryptoKeyHelper.createSharedSecretByEosKey(publicKey, privateKey);
		} catch (InvalidKeyException | CryptoException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_GEN_SECRET_FAIL, e);
		}
		return sharedSecret;
	}


	@Override
	public byte[] getECIESDecryptBytes(String keyId, byte[] nonce, String publicKey, byte[] source, AESType aesType)
			throws IWException, CryptoException {
		if (!isConnect()) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);
		}

		EosPrivateKey eosPrivateKey = getPrivateKey(keyId);

		if (eosPrivateKey == null) {
			GDPLogger.debug("ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST - " + keyId);
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST.getCode(), keyId);
		}

//		byte[] decryptData = null;
//		try {
//			byte[] sharedSecret = innerGetSharedSecret(publicKey, eosPrivateKey);
//			decryptData = cryptoManager.getDecryptBytes(nonce, sharedSecret, source, aesType);
//		} catch (CryptoException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//			// 에러 처리 필요
//		}
		byte[] decryptData = null;
		byte[] sharedSecret = null;

		try {
		    sharedSecret = innerGetSharedSecret(publicKey, eosPrivateKey);
		    decryptData = cryptoKeyHelper.eciesEncDec(nonce, sharedSecret, source, aesType, Cipher.DECRYPT_MODE);
		} catch (CryptoException e) {
		    if (sharedSecret == null) {
		        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_GEN_SECRET_FAIL, e);
		    } else {
		        throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_DECRYPT_FAIL, e);
		    }
		} catch (GeneralSecurityException e) {
		    throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_AES_DECRYPT_FAIL, e);
		}


		return decryptData;
	}

}
