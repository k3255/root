package com.raonsecure.odi.agent.data.did;

import java.util.List;

import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Proof extends IWObject {
	
	@SerializedName("type")
	private String type;
	
	@SerializedName("created")
	private String created;
	
	@SerializedName("verificationMethod")
	private String verificationMethod;
	
	@SerializedName("proofPurpose")
	private String proofPurpose;
	
	@SerializedName("proofValue")
	private String proofValue;
	
	@SerializedName("proofValueList")
	private List<String> proofValueList;
	
	
	
	
	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Proof obj = gson.fromJson(val, Proof.class);
		type = obj.getType();
		created = obj.getCreated();
		verificationMethod = obj.getVerificationMethod();
		proofPurpose = obj.getProofPurpose();
		proofValue = obj.getProofValue();
		proofValueList = obj.getProofValueList();
	}	
}
