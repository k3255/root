package com.raonsecure.odi.agent.data.rest;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.vc.Claims;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ClaimsDef  extends Claims {

	@SerializedName("mandatory")
	@Expose
	private boolean mandatory = false;
	

	@Override
	public void fromJson(String val) {
		super.fromJson(val);
		GsonWrapper gson = new GsonWrapper();
		ClaimsDef obj = gson.fromJson(val, ClaimsDef.class);
		mandatory = obj.isMandatory();

	}

}
