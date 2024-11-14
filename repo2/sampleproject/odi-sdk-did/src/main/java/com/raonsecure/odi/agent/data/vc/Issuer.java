package com.raonsecure.odi.agent.data.vc;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Issuer extends IWObject {

	@SerializedName("id")
	@Expose
	private String id;
	
	@SerializedName("name")
	@Expose
	private String name;

	@SerializedName("desc")
	@Expose
	private String desc;

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Issuer obj = gson.fromJson(val, Issuer.class);
		id = obj.getId();
		name = obj.getName();
		desc = obj.getDesc();
	}	

}
