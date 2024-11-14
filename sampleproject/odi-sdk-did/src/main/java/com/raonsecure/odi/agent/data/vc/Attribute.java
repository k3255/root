package com.raonsecure.odi.agent.data.vc;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Attribute extends IWObject {

	@SerializedName("type") 
	@Expose
	private String type;
	@SerializedName("format")
	@Expose
	private String format;
	@SerializedName("hideValue")
	@Expose
	private boolean hideValue;
	@SerializedName("location")
	@Expose
	private String location;

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Attribute obj = gson.fromJson(val, Attribute.class);

		type = obj.getType();
		format = obj.getFormat();
		hideValue = obj.isHideValue();
		location = obj.getLocation();

	}
	
	
}