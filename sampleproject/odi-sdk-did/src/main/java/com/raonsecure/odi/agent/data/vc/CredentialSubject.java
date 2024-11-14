package com.raonsecure.odi.agent.data.vc;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CredentialSubject extends IWObject {
	@SerializedName("id")
	@Expose
	private String id;

	@SerializedName("extension")
	@Expose
	private Extension extension;

	@SerializedName("claims")
	@Expose
	private List<Claims> claims;

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		CredentialSubject obj = gson.fromJson(val, CredentialSubject.class);

		id = obj.getId();
		extension = obj.getExtension();
		claims = obj.getClaims();
	}
}
