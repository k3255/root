package com.raonsecure.odi.agent.data.rest;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PublicClaim extends IWObject {
	@SerializedName("code")
	@Expose
	private String code;

	@SerializedName("name")
	@Expose
	private String name;

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		PublicClaim obj = gson.fromJson(val, PublicClaim.class);
		code = obj.code;
		name = obj.name;

	}
}
