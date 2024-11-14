package com.raonsecure.odi.crypto.key.data;

import com.raonsecure.odi.crypto.ecies.EosPrivateKey;
import com.raonsecure.odi.crypto.ecies.EosPublicKey;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.util.MultiBase;

public class IWEosKey implements IWKeyPairInterface {
	
	private EosPublicKey pubKey; // optional
    private EosPrivateKey priKey;
    
    public IWEosKey(EosPublicKey pubKey, EosPrivateKey priKey) {
    	this.pubKey = pubKey;
    	this.priKey = priKey;
    }
    
    @Override
	public Object getPubKey() {
		return pubKey;
	}

    @Override
	public void setPubKey(Object pubKey) {
		this.pubKey = (EosPublicKey) pubKey;
	}

    @Override
	public Object getPriKey() {
		return priKey; 
	}
	
    @Override
	public void setPriKey(Object priKey) {
		this.priKey = (EosPrivateKey) priKey;
	}

	@Override
	public String getBase58PubKey() throws CryptoException {
		return MultiBase.encode(pubKey.getBytes(), MultiBaseEnum.Base58btc);
	}	
}
