package com.raonsecure.odi.wallet.key;

import java.util.List;

import com.raonsecure.odi.wallet.exception.IWException;

public class IWManager {

	protected String getKeyDId(String did, String keyId) {
		return did + "#" + keyId;
	}

}