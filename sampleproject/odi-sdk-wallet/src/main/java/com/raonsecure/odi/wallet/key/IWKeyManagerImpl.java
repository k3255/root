package com.raonsecure.odi.wallet.key;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.raonsecure.odi.agent.data.VerifiableClaim;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.vc.VerifiableCredential;
import com.raonsecure.odi.agent.data.vp.VerifiablePresentation;
import com.raonsecure.odi.crypto.ec.CurveParam;
import com.raonsecure.odi.crypto.ec.EcTools;
import com.raonsecure.odi.crypto.ecies.CryptoHelper;
import com.raonsecure.odi.crypto.ecies.CryptoKeyHelper;
import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.enums.CurveParamEnum;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.crypto.key.data.IWKeyPairInterface;
import com.raonsecure.odi.crypto.util.MultiBase;
import com.raonsecure.odi.wallet.exception.IWErrorCode;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.data.IWHeadElement;
import com.raonsecure.odi.wallet.key.data.IWKey;
import com.raonsecure.odi.wallet.key.data.IWKeyElement;
import com.raonsecure.odi.wallet.key.data.IWKeyStoreData;
import com.raonsecure.odi.wallet.key.data.IWKeyStoreEncodingElement;
import com.raonsecure.odi.wallet.key.data.IWKey.ALGORITHM_TYPE;
import com.raonsecure.odi.wallet.key.data.IWKeyStoreEncodingElement.ENCODING_TYPE;
import com.raonsecure.odi.wallet.key.rest.data.KeyInfo;
import com.raonsecure.odi.wallet.key.store.IWKeyFile;
import com.raonsecure.odi.wallet.key.store.IWKeyStoreDefault;
import com.raonsecure.odi.wallet.key.store.IWKeyStore.IWKeyStoreHepler;
import com.raonsecure.odi.wallet.key.store.IWKeyStore.OnResultListener;
import com.raonsecure.odi.wallet.util.json.GsonWrapper;
import com.raonsecure.oid.crypto.encoding.Base58;
import com.raonsecure.oid.crypto.encoding.Base64;
import org.spongycastle.util.encoders.Hex;

public abstract class IWKeyManagerImpl extends IWManager implements IWKeyManagerInterface {

	private IWKeyStoreHepler iwK;
	protected IWKeyFile iwF;

	protected IWKeyStoreData keyStoreData;
	protected CryptoHelper cryptoHelper = new CryptoHelper();
	protected CryptoKeyHelper cryptoKeyHelper = new CryptoKeyHelper();
	private byte[] proxyKey = null;


	private final static String ALGORITHM_VERIFICATION = "VerificationKey2018";

	/**
	 * (Default) KeyStore 생성자 : Password 인증
	 *
	 * @param walletfile_pathWithName
	 * @param pwd
	 * @throws Exception
	 */
	public IWKeyManagerImpl(char[] pwd, AESType aesType) throws IWException {
		init(null, pwd, aesType);
	}

	public IWKeyManagerImpl(byte[] pwd, AESType aesType) throws IWException {
		char[] chars = new char[pwd.length];
		for (int i = 0; i < pwd.length; i++)
			chars[i] = (char) pwd[i];
		init(null, chars, aesType);
	}


	public IWKeyManagerImpl(String walletJson, char[]  pwd) throws IWException {
		init(walletJson ,pwd, null);
	}

	public IWKeyManagerImpl(String walletfile_pathWithName) throws IWException {
		init(walletfile_pathWithName);
	}

	private void init(String walletfile_pathWithName) throws IWException {

		iwF = new IWKeyFile(walletfile_pathWithName);

		if (!iwF.isExist()) {
			// generate & save a symmetric key parameters
			IWKeyStoreData data = new IWKeyStoreData();
			IWHeadElement head = new IWHeadElement();
			head.setEncType("AES256");
			head.setIterations(2048);
			try {
				head.setSalt(Base58.encode(cryptoHelper.generateSalt()));
			} catch (CryptoException e) {
				e.printStackTrace();
			}

			IWKeyStoreEncodingElement encoding = new IWKeyStoreEncodingElement();

			encoding.setKey(ENCODING_TYPE.ENCODING_BASE58.getValue());
			encoding.setPrivacy(ENCODING_TYPE.ENCODING_HEXA_DECIMAL.getValue());

			head.setEncoding(encoding);

			data.setHead(head);
			iwF.write(data);
		}

	}

	/**
	 * (Default) KeyStore 생성자 초기화
	 *
	 * @param walletJson
	 * @param pwd
	 * @param aesType
	 * @throws IWException
	 */
	@SuppressWarnings("null")
	private void init(String walletJson, char[] pwd, AESType aesTypeForEncrypt) throws IWException {

		keyStoreData = new IWKeyStoreData();


		// generate & save a symmetric key parameters
		if(walletJson ==null || walletJson == "") {

			IWHeadElement head = new IWHeadElement();


			String aesTypeValue = aesTypeForEncrypt == AESType.AES256 ?  "AES256" : "AES128";
			head.setEncType(aesTypeValue);

			head.setIterations(2048);
			try {
				head.setSalt(MultiBase.encode(cryptoHelper.generateSalt(), MultiBaseEnum.Base58btc));
			} catch (CryptoException e) {
				throw new IWException(IWErrorCode.ERR_CODE_CRYPTOHELPER_GENSRANDOM_FAIL, e);
			}

			IWKeyStoreEncodingElement encoding = new IWKeyStoreEncodingElement();

			encoding.setKey(ENCODING_TYPE.ENCODING_BASE58.getValue());
			encoding.setPrivacy(ENCODING_TYPE.ENCODING_HEXA_DECIMAL.getValue());

			head.setEncoding(encoding);

			keyStoreData.setHead(head);

		}else {
			keyStoreData.fromJson(walletJson);
		}

		iwK = new IWKeyStoreDefault(keyStoreData);
		if (!iwK.isExistWrapKey()) {
			// generate & save a wrapKey
			iwK.genWrapKey(pwd);
		}
	}

	private void generateWrapKey(char[] pwd) throws IWException {
		iwK = new IWKeyStoreDefault(iwF);
		if (!iwK.isExistWrapKey()) {
			// generate & save a wrapKey
			iwK.genWrapKey(pwd);

		}
	}

	@Override
	public IWHeadElement getHeader() {
//		IWKeyStoreData data = null;
		IWKeyStoreData data = keyStoreData;
//		try {
//			data = keyStoreData;
//		} catch (IWException e) {
//			// TODO Auto-generated catch block
////			e.printStackTrace();
//			return null;
//		}
		IWHeadElement head = data.getHead();

		return head;
	}

	/**
	 * WrapKey를 Memory에서 로드 했는지 여부
	 *
	 * @return
	 */
	@Override
	public boolean isConnect() {
		return (proxyKey != null ? true : false);
	}

	/**
	 * WrapKey를 Memory에서 제거
	 *
	 * @return
	 */
	@Override
	public boolean disConnect() {
		if (proxyKey != null) {
			Arrays.fill(proxyKey, (byte) 0x00);
			proxyKey = null;
		}

	//	if(keyStoreData!=null) keyStoreData=null;

		return true;
	}

	/**
	 * 비밀번호 등록되어있는지 확인하기 (dlchoi)
	 *
	 *
	 */

//	@Override
//	public boolean isPasswordSet() {
//		IWHeadElement header = getHeader();
//		if (header == null) {
//			return false;
//		} else {
//			if (header.getProxyKey() == null) {
//				return false;
//			} else {
//				return true;
//			}
//		}
//
//	}

	/**
	 * WrapKey를 Memory위에 로드
	 *
	 * @param pwdOrAlias
	 * @param listener
	 * @throws Exception
	 */

//	@Override
//	public void connect(byte[] pwdOrAlias, final OnConnectListener listener) throws IWException {
//		char[] chars = new char[pwdOrAlias.length];
//		for (int i = 0; i < pwdOrAlias.length; i++)
//			chars[i] = (char) pwdOrAlias[i];
//
//		connect(chars, listener);
//	}

	@Override
	public void unlock(char[] pwdOrAlias, final OnConnectListener listener) throws IWException {

		if (pwdOrAlias == null || pwdOrAlias.length == 0) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PASSWORD);
		}

		// 없으면 생성.. 있으면 셋팅..
		generateWrapKey(pwdOrAlias);

		if (proxyKey != null) {
			listener.onSuccess();
			return;
		}


		iwK.authenticate(pwdOrAlias, new OnResultListener() {

				@Override
				public void onSuccess(byte[] result) {
					if (result != null) {
						proxyKey = new byte[result.length];
						System.arraycopy(result, 0, proxyKey, 0, result.length);
					} else {
						proxyKey = null;
					}

					listener.onSuccess();
				}

				@Override
				public void onFail(String errCode) {
					disConnect();
					listener.onFail(errCode);
				}

				@Override
				public void onCancel() {
					disConnect();
					listener.onCancel();
				}
			});



	}

	private byte[] generateDerivedKey(char[] source, AESType aesType) throws IWException {
		byte[] dk = null;

		int keyLength = (aesType == AESType.AES128)?16:32;
		// derive DK
		SecretKeySpec secret;
		try {
			secret = cryptoHelper.getSecretKeySpecWithPBKDF2(source,
					MultiBase.decode(keyStoreData.getHead().getSalt()), keyStoreData.getHead().getIterations(),
					(keyLength + 16) * 8);
			// seperate K, IV
			dk = secret.getEncoded();
//		} catch (IWException | CryptoException e) {
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			// 에러 처리 추가 필요
			e.printStackTrace();
		}

		return dk;

	}

	private String generateProxyKey(char[] source, AESType aesType) throws IWException {
		byte[] encData = null;
		try {

			int keyLength = (aesType == AESType.AES128)?16:32;

			// seperate K, IV
			byte[] dk = generateDerivedKey(source, aesType);
			SecretKey k = new SecretKeySpec(dk, 0, keyLength, "AES");
			byte[] iv = Arrays.copyOfRange(dk, keyLength, dk.length);

			// encrypt the message
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));

			encData = cipher.doFinal("raoncorp".getBytes());

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

		String proxyKey = null;
		try {
			proxyKey = MultiBase.encode(encData, MultiBaseEnum.Base58btc);
			System.out.println(proxyKey);
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return proxyKey;
	}

//	@Override
//	public void changePassword(byte[] oldPassword, byte[] newPassword, boolean autoLock, SuccessCallBack callBack) {
//
//		if (oldPassword == null || oldPassword.length == 0 || newPassword == null || newPassword.length == 0) {
//			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PASSWORD);
//			return;
//		}
//
//		char[] oldPasswordChar = new char[oldPassword.length];
//		for (int i = 0; i < oldPassword.length; i++) {
//			oldPasswordChar[i] = (char) oldPassword[i];
//		}
//
//		char[] newPasswordChar = new char[newPassword.length];
//		for (int i = 0; i < newPassword.length; i++) {
//			newPasswordChar[i] = (char) newPassword[i];
//		}
//
//		changePassword(oldPasswordChar, newPasswordChar, autoLock, callBack);
//	}

	@Override
	public void changePassword(char[] oldPassword, char[] newPassword, boolean autoLock, SuccessCallBack callBack) {

//		if (keyStoreData.toJson() != null) {
//			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_FILE_LOAD_FAIL);
//		}

		IWKeyStoreData newKeyStoreData = keyStoreData;
//		try {
//			newKeyStoreData = keyStoreData;
//		} catch (IWException e) {
//			IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
//			callBack.failure(errorCode);
//			return;
//		}
		if (newKeyStoreData == null) {
			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_FILE_LOAD_FAIL);
			return;
		}

		// ProxyKey check
		String proxyKeyString = newKeyStoreData.getHead().getProxyKey();
		if (proxyKeyString == null || proxyKeyString.length() == 0) {
			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_PASSWORD_NOT_SET);
			return;
		}

		// Check the Given Passwords each
		if (oldPassword == null || oldPassword.length == 0 || newPassword == null || newPassword.length == 0) {
			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PASSWORD);
			return;
		}
//		else if(Arrays.equals(oldPassword, newPassword)) {
//			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_PASSWORD_SAME_AS_OLD);
//			return;
//		}

		AESType aesType = (newKeyStoreData.getHead().getEncType().equals("AES128"))?AESType.AES128:AESType.AES256;

		String oldProxyKeyString = null;
		try {
			oldProxyKeyString = generateProxyKey(oldPassword, aesType);
		} catch (IWException e) {
			IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
			callBack.failure(errorCode);
			return;
		}

		if (oldProxyKeyString == null) {
			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL);
			return;
		}

		// Check the set password is the same with given one
//		if(!proxyKeyString.contentEquals(oldProxyKeyString)) {
//			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_PASSWORD_NOT_MATCH_WITH_THE_SET_ONE);
//			return;
//		}

		if (!proxyKeyString.contentEquals(oldProxyKeyString)) { // oldplassword wrong
			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_PASSWORD_NOT_MATCH_WITH_THE_SET_ONE);
			return;
		} else if (Arrays.equals(oldPassword, newPassword)) {
			callBack.failure(IWErrorCode.ERR_CODE_KEYMANAGER_PASSWORD_SAME_AS_OLD);
			return;
		}

		// Set the proxyKey to decode and decrypt
		byte[] proxyByte = null;
		try {
			proxyByte = generateDerivedKey(oldPassword, aesType);
		} catch (IWException e2) {
			IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e2.getErrorCode());
			callBack.failure(errorCode);
			return;
		}

		this.proxyKey = new byte[proxyByte.length];
		System.arraycopy(proxyByte, 0, this.proxyKey, 0, proxyByte.length);

		int encodingType = newKeyStoreData.getHead().getEncoding().getPrivacy();

		// privatekey
		int keyEncodingType = newKeyStoreData.getHead().getEncoding().getKey();

		ArrayList<IWKeyElement> keys = null;
		ArrayList<IWKeyElement> oldKeys = newKeyStoreData.getKeys();
		if (oldKeys != null) {
			keys = decryptPrivateKey(oldKeys, keyEncodingType, callBack);
		}

		String newProxyKey = null;
		try {
			newProxyKey = generateProxyKey(newPassword, aesType);
		} catch (IWException e) {
			IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
			callBack.failure(errorCode);
			return;
		}

		//set New Data Start
		IWHeadElement head = newKeyStoreData.getHead();
		head.setProxyKey(newProxyKey);
		newKeyStoreData.setHead(head);

		try {
			Arrays.fill(proxyByte, (byte) 0x00);
			proxyByte = null;

			proxyByte = generateDerivedKey(newPassword, aesType);
		} catch (IWException e2) {
			IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e2.getErrorCode());
			callBack.failure(errorCode);
			return;
		}

		Arrays.fill(this.proxyKey, (byte) 0x00);
		this.proxyKey = null;

		this.proxyKey = new byte[proxyByte.length];
		System.arraycopy(proxyByte, 0, this.proxyKey, 0, proxyByte.length);


		// encrypt privatekey
		if (keys != null && keys.size() > 0) {
			for (IWKeyElement element : keys) {

				byte[] decoded = null;
				try {
					decoded = MultiBase.decode(element.getPrivateKey());
				} catch (Exception e) {
					callBack.failure(IWErrorCode.ERR_CODE_CRYPTOHELPER_ENCRYPT);
					return;
				}

				String encodedPrivateKey = null;
				try {

					try {
						encodedPrivateKey = encrypt(decoded, keyEncodingType);
					} catch (CryptoException e) {
						// TODO Auto-generated catch block 에러 처리 필요..
						e.printStackTrace();
						IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
						callBack.failure(errorCode);
						return;
					}

				} catch (IWException e) {
					IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
					callBack.failure(errorCode);
					return;
				}

				if (encodedPrivateKey == null) {
					callBack.failure(IWErrorCode.ERR_CODE_CRYPTOHELPER_ENCRYPT);
					return;
				}

				element.setPrivateKey(encodedPrivateKey);

			}

			newKeyStoreData.setKeys(keys);
		}

//		if (autoLock == true) {
//			this.disConnect();
//		}

		callBack.success();

	}

	/**
	 * (Key Structure:keys) Remove a IWKey by keyId.
	 *
	 * @param keyId
	 * @return
	 */
	@Override
	public void removeKey(String keyId) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		IWKeyElement key = getIWKey(keyId);
		if (key == null)
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST);

		if (keyStoreData == null) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_FILE_LOAD_FAIL);
		}

		boolean isChanged = false;

		ArrayList<IWKeyElement> keys = keyStoreData.getKeys();
		for (IWKeyElement k : keys) {
			if (k.getKeyId().equals(keyId)) {
				if (keys.remove(k)) {
					isChanged = true;
					break;
				}
			}
		}

		if (isChanged == true) {
			keyStoreData.setKeys(keys);
		}

	}

	/**
	 * (Key Structure:keys) Add a IWKey.
	 *
	 * @param key
	 * @return
	 */
	@Override
	public void addKey(IWKey key) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		if (key == null) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_IWKEY_IS_NULL);
		}

//		if (key.getAlg() != ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue()) {
//			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_ALGORITHM_TYPE);
//		}

		if (key.getKeyId().equals("") || key.getKeyId() == null) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_EMPTY_NAME);
		}

		if (!key.getKeyId().matches("^[0-9a-zA-Z.]+$"))
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_KEYID_NAME);

		// privateKey, publicKey check 추가 예정
		if (key.getEosPriKey().getBytes().length != 32) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PRIVATE_KEY);
		}

		if (key.getEosPubKey().getBytes().length != 33) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PUBLIC_KEY);
		}

		// 기존 key 존재여부 검사
		if (iwF.getData() != null && iwF.getData().getKeys() != null) {
			ArrayList<IWKeyElement> keyEles = iwF.getData().getKeys();
			for (IWKeyElement keyEle : keyEles) {
				if (keyEle.getKeyId().equals(key.getKeyId())) {
					throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_ALREADY_EXIST);
				}
			}
		}

		// 기존 key 읽기
		IWKeyStoreData data = iwF.getData();
		ArrayList<IWKeyElement> keys = data.getKeys();
		if (keys == null)
			keys = new ArrayList<IWKeyElement>();


		// 새로운 key 추가
		keys.add(convertToIWKeyElement(key));
		data.setKeys(keys);
		iwF.write(data);
	}



	@Override
	public void generateRandomKeys(List<KeyInfo> keyInfos) throws IWException {

		if(keyInfos == null || keyInfos.size() == 0) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYINFO_EMPTY);
		}

		for(KeyInfo keyInfo : keyInfos) {
			generateRandomKey(keyInfo.getKeyId(), keyInfo.getAlgoType());
		}

	}
	/**
	 * (Key Structure:keys) Generate Random IWKey.
	 *
	 * @param keyId
	 * @param algType
	 * @return
	 */
	@Override
	public void generateRandomKey(String keyId, int algType) throws IWException {
		if (!isConnect()) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);
		}

		if (isExistKey(keyId)) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_ALREADY_EXIST);
		}

		if (algType != ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue() && algType != ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue()) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_ALGORITHM_TYPE);
		}

		if (keyId.equals("")) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_EMPTY_NAME);
		}

		// algo type 에 따라서  키 생성  - k1 : 0, r1 : 3
		// todo - wallet 알고리즘 타입과, CurveParamEnum 타입의 변환 API 필요
		try {
			if(algType == ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue() || algType == ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue()) {
				CurveParamEnum curveParam  = (ALGORITHM_TYPE.fromValue(algType) == ALGORITHM_TYPE.ALGORITHM_SECP256k1) ? CurveParamEnum.SECP256_K1 : CurveParamEnum.SECP256_R1;
				IWKeyPairInterface iwKeyPair = cryptoKeyHelper.createRandomKeyPairInEosKey(curveParam);
				IWKey iwKey = new IWKey(keyId, algType, (EosPublicKey)iwKeyPair.getPubKey(), (EosPrivateKey)iwKeyPair.getPriKey());
				addKey(iwKey);
			}
		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}



	}

	/**
	 * (Key Structure:keys) Get a IWKey by keyId.
	 *
	 * @param keyId
	 * @return
	 */
	@Override
	public String getPublicKey(String keyId) throws IWException {
		IWKeyElement key = getIWKey(keyId);
		if (key == null)
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST);

		return key.getPublicKey();
	}


	/**
	 * (Key Structure:keys) Get a IWKey by keyId.
	 *
	 * @param keyId
	 * @return
	 */
	// 2020.04.07 dlchoi public에서 private로 변경
	private IWKey getKeyElement(String keyId) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		IWKeyElement key = getIWKey(keyId);
		if (key == null)
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST);

		return this.getIWKeyFromIWKeyElement(key);
	}

	// dlchoi 추가
	@Override
	public String getAlgoType(String keyId) throws IWException {
		IWKey key = getKeyElement(keyId);
		ALGORITHM_TYPE algType = ALGORITHM_TYPE.fromValue(key.getAlg());

		return algType.toString();
	}

	@Override
	public ALGORITHM_TYPE getAlgoObjType(String keyId) throws IWException {
		IWKey key = getKeyElement(keyId);
		return ALGORITHM_TYPE.fromValue(key.getAlg());
	}

	@Override
	public CurveParam getKeyCurveParam(String keyId) throws IWException {
		IWKey key = getKeyElement(keyId);
		return key.getAlg()==ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue()
				? EcTools.getCurveParam(CurveParam.SECP256_R1) : EcTools.getCurveParam(CurveParam.SECP256_K1);
	}

	@Override
	public ALGORITHM_TYPE getProofAlgoType(String strProofType) throws IWException {
		if (strProofType.equals(ALGORITHM_TYPE.ALGORITHM_SECP256r1.toString() + ALGORITHM_VERIFICATION))
			return ALGORITHM_TYPE.ALGORITHM_SECP256r1;
		else if (strProofType.equals(ALGORITHM_TYPE.ALGORITHM_SECP256k1.toString() + ALGORITHM_VERIFICATION))
			return ALGORITHM_TYPE.ALGORITHM_SECP256k1;
		else
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_ALGORITHM_TYPE);
	}

	/**
	 * (Key Structure:keys) Check whether a IWKey is exist by keyId or not.
	 *
	 * @return
	 */
	@Override
	public boolean isExistKey(String keyId) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		if (getKeyIdList() != null && getKeyIdList().contains(keyId))
			return true;
		return false;
	}

// file 미사용
//	private boolean genKeyFile() throws IWException {
//		if (iwF.getWalletJson() !=null) {
//			// generate & save a symmetric key parameters
//			IWKeyStoreData data = new IWKeyStoreData();
//			IWHeadElement head = new IWHeadElement();
//			head.setEncType("AES256");
//			head.setIterations(2048);
//			try {
//				head.setSalt(MultiBase.encode(cryptoHelper.generateSalt(), MultiBaseEnum.Base58btc));
//			} catch (CryptoException e) {
//				throw new IWException(IWErrorCode.ERR_CODE_CRYPTOHELPER_GENSRANDOM_FAIL, e);
//			}
//
//			IWKeyStoreEncodingElement encoding = new IWKeyStoreEncodingElement();
//
//			encoding.setKey(ENCODING_TYPE.ENCODING_BASE58.getValue());
//			encoding.setPrivacy(ENCODING_TYPE.ENCODING_HEXA_DECIMAL.getValue());
//
//			head.setEncoding(encoding);
//
//			data.setHead(head);
//			iwF.write(data);
//			return true;
//		}
//		return false;
//	}

	/**
	 * (Key Structure:keys) Get all of the keyIds.
	 *
	 * @return
	 */
	@Override
	public List<String> getKeyIdList() throws IWException {
		List<IWKeyElement> keyEles = getIWKeyList();
		if (keyEles == null || keyEles.size() == 0) {
			return null;
		}

		List<String> keyIds = new ArrayList<String>();
		for (IWKeyElement keyId : keyEles) {
			keyIds.add(keyId.getKeyId());
		}

		return keyIds;
	}


	/**
	 * (Key Structure:keys) Get a signature by keyId.
	 *
	 * @param keyId
	 * @param source
	 * @return
	 */
	@Override
	public byte[] getSign(String keyId, byte[] source) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		return getSignBytes(keyId, source, false);
	}

	/**
	 * (Key Structure:keys) Get a signature by keyId.
	 *
	 * @param keyId
	 * @param source
	 * @param bCanonical
	 * @return
	 */
	@Override
	public byte[] getSign(String keyId, byte[] source, boolean bCanonical) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		return getSignBytes(keyId, source, bCanonical);
	}


	@Override
	public byte[] getSignWithHashData(String keyId, byte[] hashedSource) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		return getSignWithHashData(keyId, hashedSource, false);
	}

	public byte[] getSignWithHashData(String keyId, byte[] hashedSource, boolean bCanonical) throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		return getSignBytesWithHashData(keyId, hashedSource, bCanonical);
	}

	/**
	 * (Key Structure:head) Read a head.
	 *
	 * @return
	 * @throws IWException
	 */

	@Override
	public String readHeader() throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		// 기존 scheme 읽기
		IWKeyStoreData data = keyStoreData;
		return data.getHead().toJson();
	}

	/**
	 * (Key Structure) Read a key file.
	 *
	 * @return
	 * @throws IWException
	 */
	@Override
	public String readKeyStoreData() throws IWException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		// 기존 scheme 읽기
		IWKeyStoreData data = keyStoreData;
		return data.toJson();
	}

//	@Override
//	public void resetWalletFile() throws IWException {
//
//		disConnect();
//
//		if (cryptoHelper == null) {
//			cryptoHelper = new GDPCryptoHelperClient();
//		}
//
//		// generate & save a symmetric key parameters
//		IWKeyStoreData data = new IWKeyStoreData();
//		IWHeadElement head = new IWHeadElement();
//
//		if (iwF.getWalletJson() !=null) {
//			head.setEncType(iwF.getData().getHead().getEncType());
//		}
//		else {
//			head.setEncType("AES256");
//		}
//
//
//		head.setIterations(2048);
//		head.setSalt(Base58.encode(cryptoHelper.generateSalt()));
//
//		IWKeyStoreEncodingElement encoding = new IWKeyStoreEncodingElement();
//
//		encoding.setKey(ENCODING_TYPE.ENCODING_BASE58.getValue());
//		encoding.setPrivacy(ENCODING_TYPE.ENCODING_HEXA_DECIMAL.getValue());
//
//		head.setEncoding(encoding);
//
//		data.setHead(head);
//		iwF.write(data);
//
//	}

	@Override
	public void removeAllKeys() throws IWException {
		if (!isConnect()) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);
		}

		IWKeyStoreData data = keyStoreData;
		if (data == null) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_FILE_LOAD_FAIL);
		}

		ArrayList<IWKeyElement> keys = data.getKeys();

		if (keys != null && keys.size() > 0) {
			data.setKeys(null);
		}
	}

// 메소드 미사용
//	private boolean isNeedGenerateProxyKey() throws IWException {
//		// if helper is android and the keyfile is not set a proxykey yet,
//		// return true
//		IWKeyStoreData data = iwF.getData();
//		if (data == null) {
//			genKeyFile();
//		}
//		String pk = iwF.getData().getHead().getProxyKey();
//		return pk == null ? true : false;
//	}

	/*
	 * (Key Structure:keys) SECP-Private Key 암호화
	 */
	private byte[] symEncPrivateKey(byte[] privateKey) throws IWException {
		return symEncPrivateKey(privateKey, proxyKey);
	}

	private byte[] symEncPrivateKey(byte[] privateKey, byte[] key) throws IWException {
		try {
			if("AES128".equals(iwF.getData().getHead().getEncType())){
				return cryptoHelper.encrypt(key, privateKey, 16);
			}else{
				return cryptoHelper.encrypt(key, privateKey);
			}
		} catch (CryptoException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_AES_ENCRYPT_FAIL, e);
		}
	}

	/*
	 * (Key Structure:keys) SECP-Private Key 복호화
	 */

	protected byte[] symDecPrivateKey(byte[] encPrivateKey) throws IWException {
		return symDecPrivateKey(encPrivateKey, proxyKey);
	}

	protected byte[] symDecPrivateKey(byte[] encPrivateKey, byte[] key) throws IWException {
		try {
			// server
			if("AES128".equals(iwF.getData().getHead().getEncType())){
				return cryptoHelper.decrypt(key, encPrivateKey, 16);
			}else {
				return cryptoHelper.decrypt(key, encPrivateKey);
			}
		} catch (CryptoException e) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_AES_DECRYPT_FAIL, e);
		}
	}

	protected IWKeyElement getIWKey(String keyId) throws IWException {
//		IWKeyStoreData data = keyStoreData;
		IWKeyFile data = iwF;
		ArrayList<IWKeyElement> keys = data.getData().getKeys();
		if (keys == null)
			return null;

		for (IWKeyElement key : keys) {
			if (key.getKeyId().equals(keyId)) {
				return key;
			}
		}
		return null;
	}

	private List<IWKeyElement> getIWKeyList() throws IWException {
		IWKeyStoreData data = keyStoreData;
		if (data == null)
			return null;

		ArrayList<IWKeyElement> keys = data.getKeys();
		return keys;
	}


	protected IWKeyElement convertToIWKeyElement(IWKey key) throws IWException {
		IWKeyElement keyEle = new IWKeyElement();
		keyEle.setKeyId(key.getKeyId());
		keyEle.setAlg(key.getAlg());

		int encodingType = iwF.getData().getHead().getEncoding().getKey();

		try {
			String encPriKey_encodedBase58 = encrypt(getPrivateKeyBytes(key), encodingType);
			keyEle.setPrivateKey(encPriKey_encodedBase58);
			keyEle.setPublicKey(MultiBase.encode(getPublicKeyBytes(key), MultiBaseEnum.Base58btc));

		//	System.out.println("Base58! = " + MultiBase.encode(getPublicKeyBytes(key) , MultiBaseEnum.Base58btc));
		//	System.out.println("HEX! = " + MultiBase.encode(getPublicKeyBytes(key) , MultiBaseEnum.Base16));

		} catch (CryptoException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return keyEle;
	}

	// modidied by joshua
	protected String encrypt(byte[] toBeEncoded) throws IWException, CryptoException {

		return encrypt(toBeEncoded, ENCODING_TYPE.ENCODING_BASE58.getValue());
	}

	protected String encrypt(byte[] toBeEncoded, int encodingType) throws IWException, CryptoException {

		// private key
		byte[] encrypted = symEncPrivateKey(toBeEncoded);

		return encodeByte(encrypted, encodingType);

	}

	protected String encodeByte(byte[] source, int encodingType) throws CryptoException {
		String encodedString = null;

		switch (ENCODING_TYPE.fromValue(encodingType)) {
		case ENCODING_HEXA_DECIMAL: {

			encodedString = MultiBase.encode(source, MultiBaseEnum.Base16);
			break;
		}
		case ENCODING_BASE58: {

			encodedString = MultiBase.encode(source, MultiBaseEnum.Base58btc);
			break;
		}
		case ENCODING_BASE64: {

			encodedString = MultiBase.encode(source, MultiBaseEnum.Base64url);
			break;
		}
		default: {
			break;
		}
		}

		return encodedString;
	}

	protected byte[] decrypt(String toBeDecoded) throws IWException, CryptoException {

		byte[] decoded = decodeEncodedString(toBeDecoded);
		byte[] decrypted = symDecPrivateKey(decoded);

		return decrypted;
	}

	protected byte[] decodeEncodedString(String source) throws CryptoException {
		byte[] decoded = null;
		decoded = MultiBase.decode(source);
		return decoded;
	}

	protected byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
//
//	protected String byteArrayToHexString(byte[] bytes) {
//
//		StringBuilder sb = new StringBuilder();
//		for (byte b : bytes) {
//			sb.append(String.format("%02X", b & 0xff));
//		}
//		return sb.toString();
//	}

	private ArrayList<IWKeyElement> decryptPrivateKey(ArrayList<IWKeyElement> keys, int keyEncodingType,
			SuccessCallBack callback) {
		for (IWKeyElement element : keys) {
			String pKeyString = element.getPrivateKey();

			byte[] valueByte = null;
			try {
				valueByte = decrypt(pKeyString);
			} catch (IWException e) {

				IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
				callback.failure(errorCode);
			} catch (CryptoException e) {
				//  에러 처리 확인 필요..
				IWErrorCode errorCode = (IWErrorCode) IWErrorCode.getEnumByCode(e.getErrorCode());
				callback.failure(errorCode);
			}

			if (valueByte == null) {
				callback.failure(IWErrorCode.ERR_CODE_CRYPTOHELPER_DECRYPT);
			}

			try {
				element.setPrivateKey(MultiBase.encode(valueByte,MultiBaseEnum.Base58btc));
			} catch (CryptoException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		return keys;
	}
	// modified ends

	/*
	 * depends on private key type
	 *
	 * 1. SECP private key of spongy castle 2. SECP private key of eos
	 */

	protected abstract IWKey getIWKeyFromIWKeyElement(IWKeyElement iwKeyElement) throws IWException;

	protected abstract byte[] getPrivateKeyBytes(IWKey iwKey);

	protected abstract byte[] getPublicKeyBytes(IWKey iwKey);

	protected abstract byte[] getSignBytes(String keyId, byte[] source) throws IWException;

	protected abstract byte[] getSignBytes(String keyId, byte[] source, boolean bCanonical) throws IWException;

	protected abstract byte[] getSignBytesWithHashData(String keyId, byte[] hashedSource, boolean bCanonical) throws IWException;

	protected abstract void verify(byte[] pubkey_rw, byte[] source, byte[] signature, int curveParamType) throws IWException;
	protected abstract void verifyWithHashData(byte[] pubkey_rw, byte[] hashedSource, byte[] signature, int curveParamType) throws IWException;


	public boolean addCredential(String credentialJson) throws IWException, CryptoException {
		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		VerifiableCredential new_vc = new VerifiableCredential();
		new_vc.fromJson(credentialJson);

		IWKeyStoreData data = iwF.getData();

		ArrayList<String> encVcStore = data.getEncCredentials();
		if (encVcStore == null) {
			encVcStore = new ArrayList<String>();
		}

		int encodingType = data.getHead().getEncoding().getPrivacy();

		// wallet에 저장된 claim과 동일한 claim을 추가할 경우 exception 발생
		for (int i = 0; i < encVcStore.size(); i++) {
			String encData = encVcStore.get(i);
			byte[] valueByte = decrypt(encData);

			VerifiableCredential vc = new VerifiableCredential();
			vc.fromJson(new String(valueByte));

			if (vc.getId().equals(new_vc.getId())) {
				throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DUPLICATED_VC_ID);
			}
		}

		// encrypt new VC
		String encrypted_New_VC = encrypt(new_vc.toJson().getBytes(), encodingType);
		// add new VC
		encVcStore.add(encrypted_New_VC);
		data.setEncCredential(encVcStore);

		iwF.write(data);

		return true;
	}

//	public String makeRequestVerifiablePresentation(String expirationDate, ArrayList<VerifiableCredential> credentials,
//													String did, String keyId, byte[] nonce) throws IWException {
//
//		String vp = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"expirationDate\":\"2030-12-31T16:23:40\",\"holder\":\"did:omn:user\",\"id\":\"a794abc1-a715-4c96-91e0-959440df7ced\",\"proof\":[{\"created\":\"2024-01-18T04:36:38\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3qyrpfsF6yricVPvLEar687cZGn6vcHGKkKxx1dmv51wE7jqtHLqEKkvzt2LsSwbz55YEhbjM2KpCrAqvoFuvfGtH\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:user#pinKey\"}],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":{\"claims\":[{\"attribute\":{\"format\":\"plain\",\"hideValue\":true,\"location\":\"inline\",\"type\":\"text\"},\"caption\":\"이름\",\"code\":\"das.v1.name\",\"value\":\"함초롬\"},{\"attribute\":{\"format\":\"plain\",\"hideValue\":true,\"location\":\"remote\",\"type\":\"text\"},\"caption\":\"url\",\"code\":\"das.v1.url\",\"value\":\"uaHR0cDovLzE5Mi4xNjguMC44Ni9vZGk\"}],\"extension\":{\"claims\":[{\"caption\":\"닉네임\",\"code\":\"issuer.nickname\",\"value\":\"보니는천재\"}],\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3mxrx7j2qEicLot3c1zAvHBEpcHXiQgfiaYkCcbUxaAsy8vBG9Njx8uBeLw8dAbQ2f1wo9DWoJcRzersABpD69K8r\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"}]},\"id\":\"did:omn:user\"},\"encoding\":\"UTF-8\",\"evidence\":[{\"documentPresence\":\"Digital\",\"evidenceDocument\":\"k1\",\"subjectPresence\":\"Digital\",\"type\":[\"DocumentVerification\"],\"verifier\":\"did:omn:issuer\"}],\"evidenceLevel\":\"AL1\",\"expirationDate\":\"9999-12-31T23:59:59\",\"formatVersion\":\"1.0\",\"id\":\"f4cae750-422d-4d4f-990e-30d7debfb8d0\",\"issuanceDate\":\"2024-01-18T02:37:23\",\"issuer\":{\"id\":\"did:omn:issuer\",\"name\":\"issuer name\"},\"language\":\"ko\",\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValueList\":[\"z3ma7uD2Sh7ac2rKHXQieJ6UoYKrgK7MsPrf4b8aGsEHbVFX48GJFosTbK6J484UNSAFapjCvbV5cdzScjuWcgRrj7\",\"z3qvhPX13ZwiPVRdaEgpkm8vuUVmBSUuWh34hETnCV71kV6LggHtD4AtMZMNwPKsqtUBaoHdAZyBorYsriq8xu94rn\"],\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"}],\"schema\":{\"id\":\"default schema\",\"name\":\"test schema\",\"version\":\"1.0\"},\"type\":[\"VerifiableCredential\",\"IdentityCredential\"]}]}";
//
//		VerifiablePresentation verifiablePresentation = new VerifiablePresentation();
//
//
//		verifiablePresentation.setType();
//		verifiablePresentation.setId();
//		verifiablePresentation.setExpirationDate(expirationDate);
//		verifiablePresentation.setVerifiableCredential(credentials);
//
//		Proof proof = new Proof();
//
//		// proof.creator, proof.created, proof.nonce
//		byte[] signature = null;
//		{
//			// proof.creator
//			String signKeyDid;
//			if (did == null) {
//				signKeyDid = getKeyDId(credentials.get(0).getCredentialSubject().getId(), keyId);
//			} else {
//				signKeyDid = getKeyDId(did, keyId);
//			}
////			proof.setCreator(signKeyDid);
//			proof.setCreated(VerifiableClaim.dateToString(new Date()));
//
////			proof.setNonce(new String(Hex.encode(nonce)));
//
//			verifiablePresentation.setProof(proof);
//		}
//
//		// proof.sign
//		signature = getSignatureUsingKeyInKeyFile(verifiablePresentation.toJson().getBytes(), keyId, this);
//		proof.setSignatureValue(Base58.encode(signature));
//
//		// proof.type
//		IWKey key = getKeyElement(keyId);
//		ALGORITHM_TYPE algType = ALGORITHM_TYPE.fromValue(key.getAlg());
//		proof.setType(algType.toString() + ALGORITHM_VERIFICATION);
//
//		verifiablePresentation.setProof(proof);
//
//		return verifiablePresentation.toJson();
//	}

	public List<VerifiableCredential> getCredentials() throws IWException, CryptoException {

		if (!isConnect())
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_DISCONNECT);

		IWKeyStoreData data = iwF.getData();
		ArrayList<String> encCredential = new ArrayList<String>();
		encCredential = data.getEncCredentials();

		ArrayList<VerifiableCredential> credentials = new ArrayList<VerifiableCredential>();
		int encodingType = data.getHead().getEncoding().getPrivacy();

		if (encCredential != null) {
			for (int i = 0; i < encCredential.size(); i++) {
				String encData = encCredential.get(i);

				byte[] valueByte = decrypt(encData);

				VerifiableCredential vc = new VerifiableCredential();
				vc.fromJson(new String(valueByte));

				credentials.add(vc);
			}
		}

		return credentials;
		// modified ends
	}
}
