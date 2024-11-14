package com.raonsecure.odi.agent.data.vc;
import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Evidence extends IWObject{
	@SerializedName("type")
	@Expose
	private List<String> type;
	
	@SerializedName("verifier")
	@Expose
	private String verifier;
	
	@SerializedName("evidenceDocument")
	@Expose
	private String evidenceDocument;
	
	@SerializedName("subjectPresence")
	@Expose
	private String subjectPresence;
	
	@SerializedName("documentPresence")
	@Expose
	private String documentPresence;
	
	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Evidence obj = gson.fromJson(val, Evidence.class);

		type = obj.getType();
		verifier = obj.getVerifier();
		evidenceDocument = obj.getEvidenceDocument();
		subjectPresence = obj.getSubjectPresence();
		documentPresence = obj.getDocumentPresence();
	}	
}