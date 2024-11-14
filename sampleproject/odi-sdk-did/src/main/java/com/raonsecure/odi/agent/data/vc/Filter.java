package com.raonsecure.odi.agent.data.vc;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;
@Getter
@Setter
public class Filter extends IWObject {

	@SerializedName("alList")
	@Expose
	private List<String> alList;

	@SerializedName("issuerList")
	@Expose
	private List<String> issuerList;

	@SerializedName("requiredClaimList")
	@Expose
	private List<String> requiredClaimList;



	public List<String> getAlList() {

		if (alList == null) {
			return null;
		}

		List<String> lAlList = new ArrayList<String>();
		lAlList.addAll(alList);

		return lAlList;
	}

	public void setAlList(List<String> alList) {

		if (alList != null) {
			List<String> new_alList = new ArrayList<String>();
			new_alList.addAll(alList);
			this.alList = new_alList;
		} else {
			this.alList = null;
		}

	}
	
	public void setIssuerList(List<String> issuerList) {

		if (issuerList != null) {
			List<String> new_IssuerList = new ArrayList<String>();
			new_IssuerList.addAll(issuerList);
			this.issuerList = new_IssuerList;
		} else {
			this.issuerList = null;
		}

	}

	public List<String> getIssuerList() {

		if (issuerList == null) {
			return null;
		}

		List<String> lIssuerList = new ArrayList<String>();
		lIssuerList.addAll(issuerList);

		return lIssuerList;
	}
	
	public List<String> getRequiredClaimList() {

		if (requiredClaimList == null) {
			return null;
		}

		List<String> lRequiredClaimList = new ArrayList<String>();
		lRequiredClaimList.addAll(requiredClaimList);

		return lRequiredClaimList;
	}

	public void setRequiredClaimList(List<String> requiredClaimList) {

		if (requiredClaimList != null) {
			List<String> new_requiredClaimList = new ArrayList<String>();
			new_requiredClaimList.addAll(requiredClaimList);
			this.requiredClaimList = new_requiredClaimList;
		} else {
			this.requiredClaimList = null;
		}

	}

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Filter obj = gson.fromJson(val, Filter.class);
		alList = obj.getAlList();
		issuerList = obj.getIssuerList();
		requiredClaimList = obj.getRequiredClaimList();
	}
}
