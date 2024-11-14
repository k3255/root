package com.raonsecure.odi.agent.data.vc.result;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ClaimsResult extends IWObject{
	@SerializedName("code")
	@Expose
	private String code;
	@SerializedName("caption")
	@Expose
	private String caption;
	@SerializedName("type")
	@Expose
	private String type;
	@SerializedName("format")
	@Expose
	private String format;
	@SerializedName("location")
	@Expose
	private String location;
	@SerializedName("value")
	@Expose
	private String value;
	@SerializedName("hideValue")
	@Expose
	private boolean hideValue;
	@SerializedName("digestSRI")
	@Expose
	private String digestSRI;
	
	


	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		ClaimsResult obj = gson.fromJson(val, ClaimsResult.class);
		code = obj.getCode();
		caption = obj.getCaption();
		type = obj.getType();
		format = obj.getFormat();
		location = obj.getLocation();
		value = obj.getValue();
		hideValue = obj.isHideValue();
	}
}
