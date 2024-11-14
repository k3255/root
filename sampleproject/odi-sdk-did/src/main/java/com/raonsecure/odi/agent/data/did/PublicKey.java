package com.raonsecure.odi.agent.data.did;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PublicKey extends IWObject{

	/**
	 * da#keyId
	 */
	@SerializedName("id")
	@Expose
	private String id;
	/**
	 * Secp256r1VerificationKey2018, Secp256r1KeyAgrementKey2019
	 */
	@SerializedName("type")
	@Expose
	private String type;

	/**
	 * The controllers of das and tenant have their own da
	 */
	@SerializedName("controller")
	@Expose
	private String controller;

	@SerializedName("publicKeyMultibase")
	@Expose
	private String publicKeyMultibase;
	

	@SerializedName("authType")
	@Expose
	private int authType  = 1;

	@SerializedName("status")
	@Expose
	private String status;

	
	@Override
	public void fromJson(String val) {
    	GsonWrapper gson = new GsonWrapper();
		PublicKey obj = gson.fromJson(val, PublicKey.class);
		id = obj.getId();
		type = obj.getType();
		controller = obj.getController();
		publicKeyMultibase = obj.getPublicKeyMultibase();
		authType = obj.getAuthType();
		status = obj.getStatus();
	}	
}
