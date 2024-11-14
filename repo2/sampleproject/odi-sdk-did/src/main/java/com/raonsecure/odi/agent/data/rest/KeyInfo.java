package com.raonsecure.odi.agent.data.rest;

import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.enums.did.DIDMethodType;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class KeyInfo {

	@SerializedName("keyId")
	private String keyId;

	@SerializedName("publicKey")
	private String publicKey;

	@SerializedName("algoType")
	private String algoType;

	@SerializedName("methodType")
	private int methodType = DIDMethodType.ASSERTION_METHOD.getRawValue();

	@SerializedName("controller")
	private String controller;

}
