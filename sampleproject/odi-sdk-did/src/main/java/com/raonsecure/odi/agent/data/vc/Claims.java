package com.raonsecure.odi.agent.data.vc;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Claims extends IWObject {

	@SerializedName("code")
	@Expose
	private String code;
	@SerializedName("caption")
	@Expose
	private String caption;
	@SerializedName("attribute")
	@Expose
	private Attribute attribute;

	@SerializedName("digestSRI")
	@Expose
	private String digestSRI;
	@SerializedName("value")
	@Expose
	private String value;

	@Override
	public void fromJson(String val) {

		GsonWrapper gson = new GsonWrapper();
		Claims obj = gson.fromJson(val, Claims.class);

		code = obj.getCode();
		caption = obj.getCaption();
		attribute = obj.getAttribute();
		digestSRI = obj.getDigestSRI();
		value = obj.getValue();
		

	}

}
