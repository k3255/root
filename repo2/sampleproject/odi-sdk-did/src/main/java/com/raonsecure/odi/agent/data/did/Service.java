package com.raonsecure.odi.agent.data.did;

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
public class Service extends IWObject{
	
   
	@SerializedName("id")
    @Expose
    private String id;
    
	@SerializedName("serviceEndpoint")
    @Expose
    private List<String> serviceEndpoint;
    
	@SerializedName("type")
    @Expose
    private String type;
	
	public Service() {	
	}
    
	public Service(String val) {
		fromJson(val);
	}
	
	public void setServiceEndpoint(List<String> serviceUrl) {
		if (serviceUrl != null) {
			if (this.serviceEndpoint == null) {
				this.serviceEndpoint = new ArrayList<>();
			}
			this.serviceEndpoint.addAll(serviceUrl);
		} else {
			this.serviceEndpoint = null;
		}
	}
	
	@Override
    public void fromJson(String val) {
		// 비어 있는 값 파싱 에러 확인하기 
    	GsonWrapper gson = new GsonWrapper();
    	Service data = gson.fromJson(val, Service.class);
    	id  = data.getId();
    	if(data.getServiceEndpoint() !=null) {
    		serviceEndpoint = data.getServiceEndpoint();
    	}
    	type = data.getType();
    	
	}
	
}
