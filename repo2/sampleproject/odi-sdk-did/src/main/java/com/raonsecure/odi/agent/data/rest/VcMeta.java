package com.raonsecure.odi.agent.data.rest;

import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.data.vc.Issuer;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;
@Getter
@Setter
public class VcMeta extends IWObject{
	
	private String id; 
	
	private Issuer issuer; 
	
	private String subjectId; 
	
	private String issuanceDate; 
	
	private String expirationDate; 
	
	private String formatVersion; 
	
	private String schemaId; 
	
	private String status; 
	
	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		VcMeta obj = gson.fromJson(val, VcMeta.class);

		id = obj.getId();
		issuer = obj.getIssuer();
		subjectId = obj.getSubjectId();
		issuanceDate = obj.getIssuanceDate();
		expirationDate = obj.getExpirationDate();
		formatVersion = obj.getFormatVersion();
		schemaId = obj.getSchemaId();
		status = obj.getStatus();
		
	}	

}
