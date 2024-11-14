package com.raonsecure.odi.agent.data.vc;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Extension extends IWObject {

	@SerializedName("proof")
	@Expose
	private List<Proof> proof;
	@SerializedName("claims")
	@Expose
	private List<Claims> claims;

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Extension obj = gson.fromJson(val, Extension.class);
		proof = obj.getProof();
		claims = obj.getClaims();
	}
}
