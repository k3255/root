package com.raonsecure.odi.crypto.key.data;

import com.raonsecure.odi.crypto.exception.CryptoException;

public interface IWKeyPairInterface {
	
	public Object getPubKey();
	
	public void setPubKey(Object pubKey);
	
	public String getBase58PubKey() throws CryptoException;

	public Object getPriKey();
	
	public void setPriKey(Object priKey);
}
