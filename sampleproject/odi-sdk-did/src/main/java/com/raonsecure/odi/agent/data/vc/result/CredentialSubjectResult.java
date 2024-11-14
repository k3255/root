package com.raonsecure.odi.agent.data.vc.result;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CredentialSubjectResult extends IWObject{
	@SerializedName("id")
	@Expose
	private String id;
	@SerializedName("claims")
	@Expose
	private List<ClaimsResult> claimsResult;

	@Override
	public void fromJson(String val) {		
		GsonWrapper gson = new GsonWrapper();
		CredentialSubjectResult obj = gson.fromJson(val, CredentialSubjectResult.class);
		id = obj.getId();
		claimsResult = obj.getClaimsResult();
	}
}
