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
public class Condition extends IWObject{
	// 사용하지 않음 
	@SerializedName("category")
	@Expose
	private String category; 
	
	@SerializedName("schemaList")
	@Expose	
	private List<String> schemaList; 
	
	// 사용하지 않음 
	@SerializedName("displayClaimList")
	@Expose	
	private List<String> displayClaimList; 
	
	@SerializedName("filter")
	@Expose
	private Filter filter;

	@Override
	public void fromJson(String val) {

		GsonWrapper gson = new GsonWrapper();
		Condition obj = gson.fromJson(val, Condition.class);

		category = obj.getCategory();
		schemaList = obj.getSchemaList();
		displayClaimList = obj.getDisplayClaimList();
		filter = obj.getFilter();
	
		
		
	}

}
