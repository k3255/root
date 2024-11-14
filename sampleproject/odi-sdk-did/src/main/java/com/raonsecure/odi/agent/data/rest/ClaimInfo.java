package com.raonsecure.odi.agent.data.rest;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;
import com.raonsecure.odi.crypto.enums.DigestEnum;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ClaimInfo extends IWObject {

	@SerializedName("code")
	@Expose
	private String code;
	@SerializedName("value")
	@Expose
	private String value;
	@SerializedName("format")
	@Expose
	private String format;
	@SerializedName("encodeType")
	@Expose
	private String encodeType;
	@SerializedName("byteValue")
	@Expose
	private byte[] byteValue;
	@SerializedName("digestAlgoType")
	@Expose
	private String digestAlgoType = DigestEnum.Sha384.getRawValue();
	


	@Override
	public void fromJson(String val) {

		GsonWrapper gson = new GsonWrapper();
		ClaimInfo obj = gson.fromJson(val, ClaimInfo.class);

		code = obj.getCode();
		value = obj.getValue();
		encodeType = obj.getEncodeType();
		byteValue = obj.getByteValue();
		digestAlgoType = obj.getDigestAlgoType(); 
	}

}
