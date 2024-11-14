package com.raonsecure.odi.wallet.key.data;

import java.security.PrivateKey;
import java.security.PublicKey;

import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.key.data.IWEosKey;
import com.raonsecure.odi.crypto.key.data.IWJavaKey;
import com.raonsecure.odi.crypto.key.data.IWKeyPairInterface;


public class IWKey {
	private String keyId;
	//private String alg;
	private int alg;
	private IWKeyPairInterface keyPair;
	
	public enum ALGORITHM_TYPE {
	
		// crypto- sdk CurveParamEnum number 와 동일하게 수정
		ALGORITHM_SECP256k1(0), ALGORITHM_TYPE_RSA(4), ALGORITHM_TYPE_ED25519(2), ALGORITHM_SECP256r1(1);
	
		private int value;
	
		private ALGORITHM_TYPE(int value) {
			this.value = value;
		}
	
		public int getValue() {
			return value;
		}
	
		public static ALGORITHM_TYPE fromValue(int value) {
			for (ALGORITHM_TYPE type : values()) {
				if (type.getValue() == value) {
					return type;
				}
			}
			return null;
		}
	
		// 수정 필요.. 
		public static int getCurveInt(int algType) {
			return algType == ALGORITHM_TYPE.ALGORITHM_SECP256k1.getValue() ? 0 : 1;
		}
	
		@Override
		public String toString() {
			switch (this) {
			case ALGORITHM_SECP256k1:
				return "Secp256k1";
			case ALGORITHM_TYPE_RSA:
				return "RSA";
			case ALGORITHM_TYPE_ED25519:
				return "Ed25519";
			case ALGORITHM_SECP256r1:
				return "Secp256r1";
			default:
				return "Unknown";
			}
		}
	}
	
	public IWKey(String keyId, int alg, PublicKey pubKey, PrivateKey priKey) {
		super();
		this.keyId = keyId;
		this.alg = alg;
		keyPair = (IWKeyPairInterface) new IWJavaKey(pubKey, priKey);
	}
	
	public IWKey(String keyId, int alg, EosPublicKey pubKey, EosPrivateKey priKey) {
		super();
		this.keyId = keyId;
		this.alg = alg;
		keyPair = (IWKeyPairInterface) new IWEosKey(pubKey, priKey);
	}
	
	public String getKeyId() {
		return keyId;
	}
	
	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}
	
	public int getAlg() {
		return alg;
	}
	
	public void setAlg(int alg) {
		this.alg = alg;
	}
	
	public PublicKey getPubKey() {
		return (PublicKey) keyPair.getPubKey();
	}
	
	public void setPubKey(PublicKey pubKey) {
		keyPair.setPubKey(pubKey);
	}
	
	public PrivateKey getPriKey() {
		return (PrivateKey) keyPair.getPriKey();
	}
	
	public void setPriKey(PrivateKey priKey) {
		keyPair.setPriKey(priKey);
	}
	
	public EosPublicKey getEosPubKey() {
		return (EosPublicKey) keyPair.getPubKey();
	}
	
	public void setEosPubKey(EosPublicKey pubKey) {
		keyPair.setPubKey(pubKey);
	}
	
	public EosPrivateKey getEosPriKey() {
		return (EosPrivateKey) keyPair.getPriKey();
	}
	
	public void setEosPriKey(EosPrivateKey priKey) {
		keyPair.setPriKey(priKey);
	}
    
}
