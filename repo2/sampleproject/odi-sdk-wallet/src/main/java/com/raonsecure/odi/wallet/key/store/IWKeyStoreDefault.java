package com.raonsecure.odi.wallet.key.store;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.raonsecure.odi.crypto.ecies.CryptoHelper;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.util.MultiBase;
import com.raonsecure.odi.wallet.exception.IWErrorCode;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.data.IWHeadElement;
import com.raonsecure.odi.wallet.key.data.IWKeyStoreData;
import com.raonsecure.odi.wallet.key.store.IWKeyStore.IWKeyStoreHepler;
import com.raonsecure.odi.wallet.key.store.IWKeyStore.OnResultListener;
import com.raonsecure.oid.crypto.encoding.Base58;

public class IWKeyStoreDefault implements IWKeyStoreHepler {

	private IWKeyStoreData keyStoreData;
	private IWKeyFile iwF;
	private boolean isProxyKey;


    public IWKeyStoreDefault(IWKeyStoreData iwKeyStoreData) throws IWException {
    	keyStoreData = iwKeyStoreData;
    	isProxyKey = keyStoreData.getHead().getProxyKey() != null ? true : false;
    }

	public IWKeyStoreDefault(IWKeyFile keyFile) throws IWException {
		iwF = keyFile;
		isProxyKey = iwF.getData().getHead().getProxyKey() != null ? true : false;
	}

    @Override
    public boolean isExistWrapKey() {
    	return isProxyKey;
    }

    @Override
    public void genWrapKey(char [] pwd) throws IWException {

		byte[] encData = null;
		try {

			IWKeyStoreData data = iwF.getData();
			IWHeadElement head = data.getHead();

			int keyLength = (head.getEncType().equals("AES128"))?16:32;

			// derive DK
			CryptoHelper cryptoHelper = new CryptoHelper();
			SecretKeySpec secret = cryptoHelper.getSecretKeySpecWithPBKDF2(pwd,
					Base58.decode(iwF.getData().getHead().getSalt()),
					iwF.getData().getHead().getIterations(), (keyLength+16) * 8);

			// seperate K, IV
			byte[] dk = secret.getEncoded();
			SecretKey k = new SecretKeySpec(dk, 0, keyLength, "AES");
			byte[] iv = Arrays.copyOfRange(dk, keyLength, dk.length);

			// encrypt the message
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "SC");
			cipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));

			encData = cipher.doFinal("raonsecure".getBytes());

			// save

			head.setProxyKey(Base58.encode(encData));
			data.setHead(head);
			iwF.write(data);

		} catch (NoSuchAlgorithmException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		} catch (NoSuchPaddingException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		} catch (InvalidKeyException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		} catch (IllegalBlockSizeException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		} catch (BadPaddingException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL, e);
		}
    }


    @Override
    public void authenticate(char [] pwd, OnResultListener listener) throws IWException {

    	byte[] data = null;
    	try {

    		int keyLength = (iwF.getData().getHead().getEncType().equals("AES128"))?16:32;

    		// derive DK
    		CryptoHelper cryptoHelper = new CryptoHelper();
			SecretKeySpec secret = cryptoHelper.getSecretKeySpecWithPBKDF2(pwd,
					Base58.decode(iwF.getData().getHead().getSalt()),
					iwF.getData().getHead().getIterations(), (keyLength+16) * 8);

			// seperate K, IV
			byte[] dk = secret.getEncoded();
			SecretKey k = new SecretKeySpec(dk, 0, keyLength, "AES");
			byte[] iv = Arrays.copyOfRange(dk, keyLength, dk.length);

            // decrypt the secret value
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "SC");
            cipher.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));

			data = cipher.doFinal(Base58.decode(iwF.getData().getHead().getProxyKey()));
//            data = cipher.doFinal(MultiBase.decode(iwF.getData().getHead().getProxyKey()));

            // verify
            if(Arrays.equals(data, "raonsecure".getBytes())) {
            	Arrays.fill(data, (byte)0x00); // secret value
            	listener.onSuccess(dk);
            }
            else
            	listener.onFail(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_AUTHENTICATE_FAIL.getCode());
    	} catch (Exception e) {
    		listener.onFail(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_AUTHENTICATE_FAIL.getCode());
    		return;
    	}
    }

    @Override
	public void encryptKEK(char [] password, byte[] data, OnResultListener listener) throws IWException {

    }

    @Override
    public void decryptKEK(char [] password, byte[] encData, OnResultListener listener) throws IWException {

    }
}
