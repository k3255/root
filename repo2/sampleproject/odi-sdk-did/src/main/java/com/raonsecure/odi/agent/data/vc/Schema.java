package com.raonsecure.odi.agent.data.vc;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.data.rest.ClaimsDef;
import com.raonsecure.odi.agent.data.rest.PublicClaim;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Schema extends IWObject {
	@SerializedName("id")
	@Expose
	private String id;

	@SerializedName("name")
	@Expose
	private String name;

	// 신규버전
	@SerializedName("version")
	@Expose
	private String version;
	@SerializedName("claims")
	@Expose
	private List<ClaimsDef> claimsDef;

	public Schema() {

	}

	public Schema(String val) {
		fromJson(val);
	}

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Schema obj = gson.fromJson(val, Schema.class);

		id = obj.getId();
		name = obj.getName();
		version = obj.getVersion();
		claimsDef = obj.getClaimsDef();

	}
}
