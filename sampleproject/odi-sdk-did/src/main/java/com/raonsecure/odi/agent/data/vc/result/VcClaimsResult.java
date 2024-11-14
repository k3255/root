package com.raonsecure.odi.agent.data.vc.result;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.data.vc.Evidence;
import com.raonsecure.odi.agent.data.vc.Issuer;
import com.raonsecure.odi.agent.data.vc.Schema;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VcClaimsResult extends IWObject{
	@SerializedName("@context")
	@Expose
	private List<String> context;
	
	@SerializedName("id")
	@Expose
	private String id;

	@SerializedName("type")
	@Expose
	private List<String> type;
	
	@SerializedName("issuer")
	@Expose
	private Issuer issuer;

	@SerializedName("issuanceDate")
	@Expose
	private String issuanceDate;

	@SerializedName("expirationDate")
	@Expose
	private String expirationDate;
	
	@SerializedName("evidence")
	@Expose
	private List<Evidence> evidence;
	
	@SerializedName("evidenceLevel")
	@Expose
	private String evidenceLevel;
	
	@SerializedName("credentialSubject")
	@Expose
	private CredentialSubjectResult credentialSubjectResult;
	
	@SerializedName("schema")
	@Expose
	private Schema schema;
	
	@SerializedName("language")
	@Expose
	private String language;
	
	@SerializedName("encoding")
	@Expose
	private String encoding;
	
	@SerializedName("formatVersion")
	@Expose
	private String formatVersion;
	

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		VcClaimsResult obj = gson.fromJson(val, VcClaimsResult.class);
		context = obj.getContext();
		id = obj.getId();
		type = obj.getType();
		issuer = obj.getIssuer();
		issuanceDate = obj.getIssuanceDate();
		expirationDate = obj.getExpirationDate();
		evidence = obj.getEvidence();
		evidenceLevel = obj.getEvidenceLevel();	
		credentialSubjectResult = obj.getCredentialSubjectResult();
		schema = obj.getSchema();
		language = obj.getLanguage();
		encoding = obj.getEncoding();		
		formatVersion = obj.getFormatVersion();
	}

}
