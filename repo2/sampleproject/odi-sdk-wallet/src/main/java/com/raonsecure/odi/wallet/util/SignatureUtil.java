package com.raonsecure.odi.wallet.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.Arrays;

import com.raonsecure.odi.crypto.digest.Sha256;
import com.raonsecure.odi.crypto.ec.CurveParam;
import com.raonsecure.odi.crypto.ec.EcTools;
import com.raonsecure.odi.crypto.ecies.CryptoConst;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.exception.CryptoErrorCode;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.util.MultiBase;
import com.raonsecure.odi.wallet.eoscommander.crypto.ec.EcDsa;
import com.raonsecure.odi.wallet.eoscommander.crypto.ec.EcSignature;
import com.raonsecure.odi.wallet.exception.IWErrorCode;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.data.IWKey.ALGORITHM_TYPE;

public class SignatureUtil {
	
	public static final  String providerClassName = "org.spongycastle.jce.provider.BouncyCastleProvider";
	
	static {

		Provider spongeCastleProvider = null;
		try {
			Class<?> providerClass = Class.forName(providerClassName);
			spongeCastleProvider = (Provider) providerClass.getDeclaredConstructor().newInstance();
		} catch (ReflectiveOperationException e) {
			e.printStackTrace();
		}

		if (spongeCastleProvider != null) {
			Security.addProvider(spongeCastleProvider);

		}

	}
		
	public void verifySignWithHashData(String mBase58PublicKey, String mBase16HashedSource, String mBase58Signature, String algoType)
			throws IWException, CryptoException {
		
		byte[] pubkey_rw = null; 
		byte[] hashedSource = null; 
		byte[] signature_rw= null; 

		try {
			pubkey_rw = MultiBase.decode(mBase58PublicKey);
			signature_rw = MultiBase.decode(mBase58Signature);
			hashedSource = MultiBase.decode(mBase16HashedSource);
			
		} catch (CryptoException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_INVALID_DECOGING_TYPE);
		}

		if (pubkey_rw.length != 33) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PUBLIC_KEY);
		}

		if (signature_rw == null || signature_rw.length != 65) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE);
		}
	
		EcSignature ecSignature = new EcSignature(signature_rw, EcTools.getCurveParam(CurveParam.SECP256_R1));
		Sha256 hash = new Sha256(hashedSource);
		byte[] data = hash.getBytes();

		EosPublicKey pubKey = new EosPublicKey(pubkey_rw, ecSignature.curveParam);

		for (int i = 0; i < 4; i++) {
			EosPublicKey recovered = EcDsa.recoverPubKey(EcTools.getCurveParam(CurveParam.SECP256_R1), data, ecSignature, i);
			if (pubKey.equals(recovered)) {
				ecSignature.setRecid(i);
				// success
				return;
			}
		}

		if (ecSignature.recId < 0) {

			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_NOT_FIND_RECID);
		}
		
		throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_VERIFY_SIGN_FAIL);

	}
	
	public byte[] convertSignDataToEos(byte[] signature_rw, byte[] hashedSource, byte[] publicKeyBytes, String algoType)
			throws IWException {
		// 곡선 및 포인트 정보 추출

		// EosKey to EcKey
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");

		ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN());
		java.security.spec.ECPoint point = ECPointUtil.decodePoint(params.getCurve(), publicKeyBytes);
		PublicKey publicKey;
		try {
			publicKey = KeyFactory.getInstance("ECDSA", CryptoConst.Provider_SC)
					.generatePublic(new java.security.spec.ECPublicKeySpec(point, params));
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_FAIL_CONVERT_EOSTYPE);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_FAIL_CONVERT_EOSTYPE);
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_FAIL_CONVERT_EOSTYPE);
		}
		ECPublicKey ecPublicKey = (ECPublicKey) publicKey;

		ByteArrayInputStream inStream = new ByteArrayInputStream(signature_rw);
		ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
		ASN1Primitive asn1 = null;
		try {
			asn1 = asnInputStream.readObject();
		} catch (IOException e) {
			e.printStackTrace();
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE);
		}
		if (!(asn1 instanceof ASN1Sequence)) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE);
		}

		ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
		ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
		if (asn1Encodables.length != 2) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE);
		}

		ASN1Integer asn1IntegerR = (ASN1Integer) asn1Encodables[0].toASN1Primitive();
		ASN1Integer asn1IntegerS = (ASN1Integer) asn1Encodables[1].toASN1Primitive();
		BigInteger integerR = asn1IntegerR.getValue();
		BigInteger integerS = asn1IntegerS.getValue();
		
		if((integerR.toByteArray().length != 32 || integerS.toByteArray().length != 32)) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_R_S_VALUE);
		}
		
		if ((true && (integerR.toByteArray().length != 32 || integerS.toByteArray().length != 32))
				|| (integerR.toByteArray().length == 33 && integerR.toByteArray()[0] == 0
						&& integerR.toByteArray()[1] == -1 && integerR.toByteArray()[2] < 0)) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE);
		}

		if (integerS.compareTo(EcTools.getCurveParam(CurveParam.SECP256_R1).halfCurveOrder()) == 1) {
			integerS = EcTools.getCurveParam(CurveParam.SECP256_R1).n().subtract(integerS);
		}

		byte[] r = new byte[33];
		byte[] s = new byte[33];
		System.arraycopy(integerR.toByteArray(), 0, r, r.length - integerR.toByteArray().length,
				integerR.toByteArray().length);
		System.arraycopy(integerS.toByteArray(), 0, s, s.length - integerS.toByteArray().length,
				integerS.toByteArray().length);
		org.spongycastle.math.ec.ECPoint q = EC5Util.convertPoint(ecPublicKey.getParams(), ecPublicKey.getW(), false);
		byte recoveryId = getRecoveryId(r, s, hashedSource, q.getEncoded(true), CurveParam.SECP256_R1);
		if (recoveryId < 0) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_NOT_FIND_RECID);
		}

		byte[] allByteArray = new byte[65];

		ByteBuffer buff = ByteBuffer.wrap(allByteArray);
		Integer rid = (int) (recoveryId);

		int intRid = rid + 27 + 4;

		buff.put((byte) (intRid));
		buff.put(Arrays.copyOfRange(r, 1, r.length));
		buff.put(Arrays.copyOfRange(s, 1, s.length));

		byte[] combined = buff.array();
		// System.out.println("SIG Result: " + Hex.toHexString(combined));

		return combined;

	}
	
	public void verifySign(String mBase58PublicKey, String source,  String mBase58Signature, String algoType) throws IWException, CryptoException {
		
		byte[] pubkey_rw = null; 
		byte[] source_rw = null; 
		byte[] signature_rw= null; 
		
		try {
			pubkey_rw = MultiBase.decode(mBase58PublicKey);
			signature_rw = MultiBase.decode(mBase58Signature);
			source_rw =source.getBytes();
		} catch (CryptoException e) {
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_INVALID_DECOGING_TYPE);
		}

		if (pubkey_rw.length != 33) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_PUBLIC_KEY);
		}

		if (signature_rw == null || signature_rw.length != 65) {
			throw new IWException(IWErrorCode.ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE);
		}
		
		
		CurveParam curveParam = ( algoType.equals(ALGORITHM_TYPE.ALGORITHM_SECP256r1.toString()))
				? EcTools.getCurveParam(CurveParam.SECP256_R1) : EcTools.getCurveParam(CurveParam.SECP256_K1);

		EcSignature ecSignature = new EcSignature(signature_rw, curveParam);

		Sha256 hash = Sha256.from(source_rw);
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
	
	private byte getRecoveryId(byte[] sigR, byte[] sigS, byte[] message, byte[] publicKey, int nCurveType) {
		ECNamedCurveParameterSpec spec = (nCurveType == CurveParam.SECP256_K1)
				? ECNamedCurveTable.getParameterSpec("secp256k1") : ECNamedCurveTable.getParameterSpec("secp256r1");
		
		BigInteger pointN = spec.getN();
		for (int recoveryId = 0; recoveryId < 2; recoveryId++) {
			try {
				BigInteger pointX = new BigInteger(1, sigR);

				X9IntegerConverter x9 = new X9IntegerConverter();
				byte[] compEnc = x9.integerToBytes(pointX, 1 + x9.getByteLength(spec.getCurve()));
				compEnc[0] = (byte) ((recoveryId & 1) == 1 ? 0x03 : 0x02);
				ECPoint pointR = spec.getCurve().decodePoint(compEnc);
				if (!pointR.multiply(pointN).isInfinity()) {
					continue;
				}

				BigInteger pointE = new BigInteger(1, message);
				BigInteger pointEInv = BigInteger.ZERO.subtract(pointE).mod(pointN);
				BigInteger pointRInv = new BigInteger(1, sigR).modInverse(pointN);
				BigInteger srInv = pointRInv.multiply(new BigInteger(1, sigS)).mod(pointN);
				BigInteger pointEInvRInv = pointRInv.multiply(pointEInv).mod(pointN);
				ECPoint pointQ = ECAlgorithms.sumOfTwoMultiplies(spec.getG(), pointEInvRInv, pointR, srInv);
				byte[] pointQBytes = pointQ.getEncoded(true);

			//	GDPLogger.debug("pointQBytes: " + Hex.toHexString(pointQBytes));

				boolean matchedKeys = true;
				for (int j = 0; j < publicKey.length; j++) {
					if (pointQBytes[j] != publicKey[j]) {
						matchedKeys = false;
						break;
					}
				}
				if (!matchedKeys) {
					continue;
				}
				return (byte) (0xFF & recoveryId);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		return (byte) 0xFF;
	}
}
