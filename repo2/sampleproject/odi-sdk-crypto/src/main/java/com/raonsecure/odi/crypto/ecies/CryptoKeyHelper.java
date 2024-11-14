package com.raonsecure.odi.crypto.ecies;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;

/**
 * Server용 Crypto 함수 구현부
 * <pre>History:</b>
 *		Eliot, 2018.09.13 최초작성
 * </pre>
 *
 * @author Eliot
 * @version 1.0
 * @see None
 */

import org.spongycastle.util.Arrays;

import com.raonsecure.odi.crypto.digest.Sha256;
import com.raonsecure.odi.crypto.digest.Sha512;
import com.raonsecure.odi.crypto.ec.CurveParam;
import com.raonsecure.odi.crypto.ec.EcTools;
import com.raonsecure.odi.crypto.enums.CurveParamEnum;
import com.raonsecure.odi.crypto.exception.CryptoErrorCode;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.key.data.AESType;
import com.raonsecure.odi.crypto.key.data.IWEosKey;
import com.raonsecure.odi.crypto.key.data.IWJavaKey;
import com.raonsecure.odi.crypto.key.data.IWKeyPairInterface;
import com.raonsecure.odi.crypto.util.MultiBase;

public class CryptoKeyHelper extends CryptoHelperInterface {
	
	// 임시 키 쌍 생성
	public IWKeyPairInterface createRandomKeyPair(CurveParamEnum curveParam) throws CryptoException {

		if (CurveParam.SECP256_K1 != curveParam.getNumber() && CurveParam.SECP256_R1 != curveParam.getNumber()) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_INVALID_ALGORITHM_TYPE);
		}
		IWKeyPairInterface iwKeyPair  = null;
	
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance(CryptoConst.ALG_ECDSA, CryptoConst.Provider_SC);
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveParam.getValue());
			g.initialize(ecSpec, SecureRandom.getInstance(CryptoConst.ALG_NONCE));

			KeyPair keyPair = g.generateKeyPair();
			iwKeyPair = new IWJavaKey(keyPair.getPublic(), keyPair.getPrivate());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_GEN_RANDOM_KEY_FAIL);
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_GEN_RANDOM_KEY_FAIL);
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_GEN_RANDOM_KEY_FAIL);
		}

		return iwKeyPair;

	}
	
	public IWKeyPairInterface createRandomKeyPairInEosKey(CurveParamEnum curveParam) throws CryptoException {

		if (CurveParam.SECP256_K1 != curveParam.getNumber() && CurveParam.SECP256_R1 != curveParam.getNumber()) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_INVALID_ALGORITHM_TYPE);
		}

		EosPrivateKey eosPrivateKey = new EosPrivateKey(curveParam.getNumber());

		IWKeyPairInterface iwKeyPair = new IWEosKey(eosPrivateKey.getPublicKey(), eosPrivateKey);

		return iwKeyPair;

	}
	
	// 자바 키 타입 -> EOS 키 타입으로 변환
	public EosPrivateKey convertKeytoEosPrivateKey(ECPrivateKey priKey) {
//		ECNamedCurveSpec curveSpec = (ECNamedCurveSpec) priKey.getParams();
//		String curveName = curveSpec.getName();
		java.security.spec.ECParameterSpec ecParameterSpec = priKey.getParams();
        String curveName = ecParameterSpec.getCurve().toString();
		int curveParam = curveName.equals(CurveParamEnum.SECP256_K1.getValue()) ? 0 : 1;
		
		EosPrivateKey eosPrivateKey = new EosPrivateKey(curveParam, priKey.getS().toByteArray());
		return eosPrivateKey;
	}

	// 자바 키 타입 -> EOS 키 타입으로 변환
	public EosPublicKey convertKeytoEosPublicKey(ECPublicKey pubKey) {
//		ECNamedCurveSpec curveSpec = (ECNamedCurveSpec) pubKey.getParams();
//		String curveName = curveSpec.getName();
		java.security.spec.ECParameterSpec ecParameterSpec = pubKey.getParams();
        String curveName = ecParameterSpec.getCurve().toString();
		int curveParam = curveName.equals(CurveParamEnum.SECP256_K1.getValue()) ? 0 : 1;
		
		BCECPublicKey bcecPublicKey = null;
		if (pubKey instanceof BCECPublicKey) {
			bcecPublicKey = (BCECPublicKey) pubKey;
		}
		else {
			bcecPublicKey = new BCECPublicKey(pubKey, null);
		}

		EosPublicKey eosPublicKey = new EosPublicKey(bcecPublicKey.getQ().getEncoded(true), EcTools.getCurveParam(curveParam));
		return eosPublicKey;
	}
	
	// SharedSecret 생성 - 자바 키
	public byte[] createSharedSecretByJavaKey(String pubKey, ECPrivateKey priKey)
			throws CryptoException, InvalidKeyException {
		ECPublicKey EcpublicKey = null;
//		ECNamedCurveSpec curveSpec = (ECNamedCurveSpec) priKey.getParams();
//		String curveName = curveSpec.getName();
		java.security.spec.ECParameterSpec ecParameterSpec = priKey.getParams();
        String curveName = ecParameterSpec.getCurve().toString();

        int curveParam = curveName.equals(CurveParamEnum.SECP256_K1.getValue()) ? 0 : 1;

		try {
			byte[] decodedPublicKey = MultiBase.decode(pubKey);
			EcpublicKey = getPublicKey(decodedPublicKey, curveParam);
		} catch (Exception e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PUBLIC_KEY);
		}

		CipherParameters ciPubKey = ECUtil.generatePublicKeyParameter(EcpublicKey);
		ECPublicKeyParameters pub = (ECPublicKeyParameters) ciPubKey;
		ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(priKey);
		org.spongycastle.math.ec.ECPoint P = pub.getQ().multiply(privKey.getD()).normalize();

		if (P.isInfinity()) {
			throw new IllegalStateException("Infinity is not a valid agreement value for ECDH");
		}

		BigInteger bitInt = P.getAffineXCoord().toBigInteger();

		byte[] sharedSecret = getBytes(bitInt);
		
	//	String encodingSharedSecret = MultiBase.encode(sharedSecret, MultiBaseEnum.Base58btc);
	//	log.info("sharedSecret  ::: {} ", encodingSharedSecret);
		
	//	return encodingSharedSecret;
		
		return sharedSecret; 
	}
	
	//
	public ECPrivateKey getPrivateKey(String priKey) throws GeneralSecurityException, CryptoException {
		byte[] priKeyBytes = MultiBase.decode(priKey);
		KeyFactory keyFact = KeyFactory.getInstance(CryptoConst.Provider_EC, CryptoConst.Provider_SC);

		PrivateKey privateKey = keyFact.generatePrivate(new PKCS8EncodedKeySpec(priKeyBytes));

		return (ECPrivateKey) privateKey;
	}
	
	// Base58 디코딩된 자바 공개키 -> 자바 공개키 변환
	public ECPublicKey getPublicKey(byte[] pubKeyBytes, int curveParam) throws GeneralSecurityException {

//		KeyFactory keyFact = KeyFactory.getInstance(CryptoConst.Provider_EC, CryptoConst.Provider_SC);
//
//		PublicKey publicKey = keyFact.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
		
        String curveName = curveParam==0 ? "secp256k1" : "secp256r1";

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);

        org.spongycastle.math.ec.ECPoint ecPoint = spec.getCurve().decodePoint(pubKeyBytes);

        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(ecPoint, spec);

        KeyFactory keyFactory = KeyFactory.getInstance(CryptoConst.Provider_EC, CryptoConst.Provider_SC);

        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);

		return (ECPublicKey) publicKey;
	}
	
	// SharedSecret 생성 - EOS 키
	public byte[] createSharedSecretByEosKey(String pubKey, EosPrivateKey priKey) throws InvalidKeyException, CryptoException {

		CurveParam curveParam = priKey.getCurveParam();
		ECPrivateKey ecPrivateKey = eosPriKeyToECPriKey(priKey.getBytes(), curveParam.getCurveParamType());
		ECPublicKey otherPublicKey = null;

		try {
			byte[] decodedPublicKey = MultiBase.decode(pubKey);
			otherPublicKey = getEcPublicKey(decodedPublicKey, curveParam.getCurveParamType());
		} catch (Exception e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PUBLIC_KEY);
		}

		CipherParameters ECpubKey = ECUtil.generatePublicKeyParameter((PublicKey) otherPublicKey);

		ECPublicKeyParameters pub = (ECPublicKeyParameters) ECpubKey;
		ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter((PrivateKey) ecPrivateKey);
		org.spongycastle.math.ec.ECPoint P = pub.getQ().multiply(privKey.getD()).normalize();

		if (P.isInfinity()) {
			throw new IllegalStateException("Infinity is not a valid agreement value for ECDH");
		}

		BigInteger bitInt = P.getAffineXCoord().toBigInteger();

		byte[] sharedSecret = getBytes(bitInt);
		
	//	String encodingSharedSecret = MultiBase.encode(sharedSecret, MultiBaseEnum.Base58btc);
	//	log.info("sharedSecret  ::: {} ", encodingSharedSecret);
		
	//	return encodingSharedSecret;
		
		return sharedSecret;
	}
	
	// Eos 키 타입 -> 자바 키 타입 변환
	public ECPrivateKey eosPriKeyToECPriKey(byte[] eosPriKeyBytes, int curveParam) {

		CurveParamEnum cParam;
		if (curveParam == 0) {
			cParam = CurveParamEnum.SECP256_K1;
		} else {
			cParam = CurveParamEnum.SECP256_R1;
		}

		try {
			System.out.println("eosPriKeyToECPriKey : " + eosPriKeyBytes.length + " / " + MultiBase.encode(eosPriKeyBytes, MultiBaseEnum.Base58btc));
			AlgorithmParameters parameters = AlgorithmParameters.getInstance(CryptoConst.Provider_EC, CryptoConst.Provider_SC);
			parameters.init(new ECGenParameterSpec(cParam.getValue()));

			java.security.spec.ECParameterSpec ecParameterSpec = parameters
					.getParameterSpec(java.security.spec.ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(eosPriKeyBytes), ecParameterSpec);

			ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance(CryptoConst.ALG_ECDSA, CryptoConst.Provider_SC)
					.generatePrivate(ecPrivateKeySpec);

			return privateKey;
		} catch (NoSuchAlgorithmException e) {
			return null;
		} catch (InvalidKeySpecException ie) {
			return null;
		} catch (NoSuchProviderException npe) {
			return null;
		} catch (InvalidParameterSpecException e) {
			return null;
		} catch (Exception e) {
			return null;
		}
	}
	
	// 디코딩 된 EOS 공개 키 -> 자바 타입 공개 키 변환
	public ECPublicKey getEcPublicKey(byte[] pubKeyBytes, int curveParam) throws GeneralSecurityException {

		CurveParamEnum cParam;
		if (curveParam == 0) {
			cParam = CurveParamEnum.SECP256_K1;
		} else {
			cParam = CurveParamEnum.SECP256_R1;
		}

		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(cParam.getValue());

		ECNamedCurveSpec params = new ECNamedCurveSpec(cParam.getValue(), spec.getCurve(), spec.getG(), spec.getN());
		ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKeyBytes);
		
		PublicKey publicKey = KeyFactory.getInstance(CryptoConst.ALG_ECDSA, CryptoConst.Provider_SC)
				.generatePublic(new java.security.spec.ECPublicKeySpec(point, params));

		return (ECPublicKey) publicKey;
	}

	private byte[] getBytes(BigInteger bigint) {
		byte[] result = new byte[32];
		byte[] bytes = bigint.toByteArray();
		if (bytes.length <= result.length) {
			System.arraycopy(bytes, 0, result, result.length - bytes.length, bytes.length);
		} else {
			assert bytes.length == 33 && bytes[0] == 0;
			System.arraycopy(bytes, 1, result, 0, bytes.length - 1);
		}
		return result;
	}

	/**
	 * AES Key를 사용해서 암/복호화
	 * @param nonce 
	 * @param key
	 * @param data
	 * @return
	 * @throws CryptoException 
	 */
	public byte[] eciesEncDec(byte[] nonce, byte[] sharedSecret, byte[] source, AESType aesType, int mode)
			throws GeneralSecurityException, CryptoException {

		byte[] hash = null;
		byte[] k = null;
		byte[] iv = null;

		byte[] nonceAndSecret = Arrays.concatenate(nonce, sharedSecret);
		
		if (aesType == AESType.AES128) {
			Sha256 sha256 = Sha256.from(nonceAndSecret);
			hash = sha256.getBytes();
		} else {
			Sha512 sha512 = Sha512.from(nonceAndSecret);
			hash = sha512.getBytes();
		}
		// length를 24로 하게설정 
		int length = aesType == AESType.AES256 ? 32 : 16;
		k = Arrays.copyOfRange(hash, 0, length);
		iv = Arrays.copyOfRange(hash, length, length + 16);
		byte[] data = null;

		// Secret Key
		SecretKey sKey = new SecretKeySpec(k, 0, k.length, "AES");

		// Secret Key IV
		AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

		// Secret Key Algorithm
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(mode, sKey, ivSpec);
		data = cipher.doFinal(source);

		if (hash != null)
			Arrays.fill(hash, (byte) 0);

		if (k != null)
			Arrays.fill(k, (byte) 0);

		if (iv != null)
			Arrays.fill(iv, (byte) 0);
		
	//	String encodingDate = MultiBase.encode(data, MultiBaseEnum.Base58btc);
		
	//	return encodingDate;
		
		return data;
	}

	// 인코딩 된 EOS타입 개인키 변환
	public EosPrivateKey getEosPrivateKeyByString(String priKey, CurveParamEnum curveParam) throws CryptoException {
		byte[] priKeyBytes = MultiBase.decode(priKey);
		EosPrivateKey privateKey = new EosPrivateKey(curveParam.getNumber(), priKeyBytes);

		return privateKey;
	}
}
