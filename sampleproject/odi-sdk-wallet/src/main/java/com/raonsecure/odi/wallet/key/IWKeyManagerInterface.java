package com.raonsecure.odi.wallet.key;
import java.security.PublicKey;
import java.util.List;

import com.raonsecure.odi.crypto.ec.CurveParam;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.wallet.exception.IWErrorCode;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.data.IWHeadElement;
import com.raonsecure.odi.wallet.key.data.IWKey;
import com.raonsecure.odi.wallet.key.data.IWKey.ALGORITHM_TYPE;
import com.raonsecure.odi.wallet.key.rest.data.KeyInfo;


public interface IWKeyManagerInterface {

	public static interface OnConnectListener {
		void onSuccess();
		void onFail(String errCode);
		void onCancel();
	}

	public interface SuccessCallBack {
		public void success();
		public void failure(IWErrorCode errorCode);
	}

	public IWHeadElement getHeader();

	public boolean disConnect();

	public void unlock(char [] pwdOrAlias, OnConnectListener listener) throws IWException;

	public void changePassword(char[] oldPassword, char[] newPassword, boolean autoLock, SuccessCallBack callBack) throws IWException;

	public boolean isConnect();

	public void addKey(IWKey key) throws IWException;

	public void generateRandomKey(String keyId, int algType) throws IWException;

	public void generateRandomKeys(List<KeyInfo> keyInfos) throws IWException;

	public void removeKey(String keyId) throws IWException;

	public void removeAllKeys() throws IWException;

	public byte[] getSignWithHashData(String keyId, byte[] hashedSource) throws IWException;

	public byte[] getSign(String keyId, byte[] source) throws IWException;

	public byte[] getSign(String keyId, byte[] source, boolean bCanonical) throws IWException;

	public String getPublicKey(String keyId) throws IWException;

	public boolean isExistKey(String keyId) throws IWException;

	public String getAlgoType(String keyId) throws IWException;

	public List<String> getKeyIdList() throws IWException;

	public String readKeyStoreData() throws IWException;

	public String readHeader() throws IWException;

	public byte[] getSharedSecret(String keyId, String publicKey) throws IWException;

	public byte[] getECIESEncryptBytes(String keyId, byte[] nonce, String publicKey, byte[] source, AESType aesType) throws IWException, CryptoException;

	public byte[] getECIESDecryptBytes(String keyId, byte[] nonce, String publicKey, byte[] source, AESType aesType) throws IWException, CryptoException;

	public ALGORITHM_TYPE getProofAlgoType(String strProofType) throws IWException;

	public ALGORITHM_TYPE getAlgoObjType(String keyId) throws IWException;

	public CurveParam getKeyCurveParam(String keyId) throws IWException;


}

