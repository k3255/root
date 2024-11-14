package com.raonsecure.odi.wallet.key;

import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.wallet.exception.IWErrorCode;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.data.IWHeadElement;
import com.raonsecure.odi.wallet.key.data.IWKey;
import com.raonsecure.odi.wallet.key.extend.IWEosKeyManagerAdapter;

public class IWKeyManager extends IWEosKeyManagerAdapter {
	/**
	 * (Default) KeyStore 생성자 : Password 인증
	 *
	 * @param pwd
	 * @param aesType
	 * @throws Exception
	 */

	public void generateRandomKey(String keyId, int algType) throws IWException {

		if (isExistKey(keyId)) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_ALREADY_EXIST);
		}

//		if (algType != IWKey.ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue()) {
//			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_ALGORITHM_TYPE);
//		}

		EosPrivateKey eosPriKey = new EosPrivateKey(algType);
		EosPublicKey eosPubKey = eosPriKey.getPublicKey();

		if (keyId.equals("")) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_EMPTY_NAME);
		}

		IWKey iwKey = new IWKey(keyId, algType, eosPubKey, eosPriKey);

		addKey(iwKey);
	}

	public boolean isPasswordSet() {
		IWHeadElement header = getHeader();
		if (header == null) {
			return false;
		} else {
			if (header.getProxyKey() == null) {
				return false;
			} else {
				return true;
			}
		}

	}

	public IWKeyManager(char[] pwd, AESType aesType) throws IWException {
		super(pwd, aesType);
	}

	/**
	 * (Default) KeyStore 생성자 : Password 인증
	 *
	 * @param walletJson
	 * @param pwd
	 * @throws Exception
	 */
	public IWKeyManager(String walletJson, char[] pwd) throws IWException {
		super(walletJson, pwd);
	}

	public IWKeyManager(String walletfile_pathWithName) throws IWException {
		super(walletfile_pathWithName);
	}
}
