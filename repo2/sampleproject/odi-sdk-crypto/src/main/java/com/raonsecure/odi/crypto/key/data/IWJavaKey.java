package com.raonsecure.odi.crypto.key.data;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.util.MultiBase;

public class IWJavaKey implements IWKeyPairInterface {
	
    private PublicKey pubKey; // optional
    private PrivateKey priKey;
    
    public IWJavaKey(PublicKey pubKey, PrivateKey priKey) {
    	this.pubKey = pubKey;
    	this.priKey = priKey;
    }
    
    @Override
	public Object getPubKey() {
		return pubKey;
	}

    @Override
	public void setPubKey(Object pubKey) {
		this.pubKey = (PublicKey) pubKey;
	}

    @Override
	public Object getPriKey() {
		return priKey; 
	}
	
    @Override
	public void setPriKey(Object priKey) {
		this.priKey = (PrivateKey) priKey;
	}

	@Override
	public String getBase58PubKey() throws CryptoException {
		ECPublicKey pubKey = (ECPublicKey) this.pubKey;
		return MultiBase.encode(pubKey.getEncoded(), MultiBaseEnum.Base58btc);
	}
}
