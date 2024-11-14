package com.raonsecure.odi.wallet.key.rest.data;

import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.wallet.data.IWObject;
import com.raonsecure.odi.wallet.util.json.GsonWrapper;

public class KeyInfo extends IWObject {

	@SerializedName("keyId")
	private String keyId;

	@SerializedName("algoType")
	private int algoType;

	@SerializedName("publicKey")
	private String publicKey;

	public String getKeyId() {
		return keyId;
	}

	public void setKeyId(String keyId) {
		this.keyId = keyId;
	}

	public int getAlgoType() {
		return algoType;
	}

	public void setAlgoType(int algoType) {
		this.algoType = algoType;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = GsonWrapper.getGson();

		KeyInfo obj = gson.fromJson(val, KeyInfo.class);
		keyId = obj.getKeyId();
		algoType = obj.getAlgoType();
		publicKey = obj.getPublicKey();
	}

}
