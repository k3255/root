package com.raonsecure.odi.agent.data.rest;

import java.util.List;

import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.enums.did.ServiceType;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ServiceInfo {
	
	@SerializedName("serviceUrl")
	private List<String> serviceUrl;
	
	// LinkedDomains, LinkedDocuments
	@SerializedName("serviceType")
	private ServiceType serviceType;


	
}