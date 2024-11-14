package com.raonsecure.odi.agent.data.vp;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.vc.VerifiableCredential;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerifiablePresentation extends IWObject {
	@SerializedName("@context")
	@Expose
	private List<String> context;
	
	@SerializedName("expirationDate")
	@Expose
	private String expirationDate;
	
	@SerializedName("holder")
	@Expose
	private String holder;
	
	@SerializedName("id")
	@Expose
	private String id;
	
	@SerializedName("proof")
	@Expose
	private List<Proof> proof;
	
	@SerializedName("type")
	@Expose
	private List<String> type;
	
	@SerializedName("verifiableCredential")
	@Expose
	private List<VerifiableCredential> verifiableCredential;
	
	public String getIssuerDid() {
		if(this.verifiableCredential == null || this.verifiableCredential.isEmpty()) {
			return null; 
		}
		
		VerifiableCredential verifiableCredential = this.verifiableCredential.get(0);
		
		if(verifiableCredential.getIssuer() == null) {
			return null; 
		}
				
		return verifiableCredential.getIssuer().getId();
	}
	
	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		VerifiablePresentation obj = gson.fromJson(val, VerifiablePresentation.class);
		context = obj.getContext();
		expirationDate = obj.getExpirationDate();
		id = obj.getId();
		proof = obj.getProof();
		type = obj.getType();
		verifiableCredential = obj.getVerifiableCredential();
		holder = obj.getHolder();
	}
	
}
