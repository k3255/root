package com.raonsecure.odi.agent.data;

import com.raonsecure.odi.agent.util.GDPJsonSortUtil;
import com.raonsecure.odi.agent.util.GsonWrapper;

public abstract class IWObject {
	
	public String toJson() {
		GsonWrapper gson = new GsonWrapper();
		String json = gson.toJson(this);
		return GDPJsonSortUtil.sortJsonString(gson, json);
//		return json;
	}
	
	public abstract void fromJson(String val);	
}

