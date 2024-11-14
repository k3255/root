package com.raonsecure.odi.agent.data.rest;

import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;
@Getter
@Setter
public class SignatureParams extends IWObject{
	

	// addproof 할 때도  필요한 값 
	@SerializedName("keyId")
	private String keyId;
	

	// addproof 할 때 필요한 값 
	@SerializedName("keyPurpose")
	private String keyPurpose;
	
	
	// addproof 할 때 필요한 값 
	@SerializedName("keyType")
	private String keyType;
	
	// 서명 hash
	@SerializedName("hashedData")
	private String hashedData;
	
	// 서명 검증 요청 때 필요한 값 
	@SerializedName("publicKey")
	private String publicKey;
	
	// 서명 원문 
	//addproof 할 때도  필요한 값 
	@SerializedName("data")
	private String data;
	
	
	//  wallet server 에서 전달받음 
	@SerializedName("algString")
	private String algString;
	
	//  wallet server 에서 전달받음 
	@SerializedName("signatureValue")
	private String signatureValue;

	@Override
	public void fromJson(String val) {
	  	GsonWrapper gson = new GsonWrapper();
	  	SignatureParams params = gson.fromJson(val, SignatureParams.class);
	  	
	  	keyId = params.getKeyId();
	  	data = params.getData();
	  	hashedData = params.getHashedData();
	  	
		
	}


}
