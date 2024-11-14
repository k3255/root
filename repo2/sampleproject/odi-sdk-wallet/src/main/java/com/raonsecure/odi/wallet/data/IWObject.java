package com.raonsecure.odi.wallet.data;

import com.raonsecure.odi.wallet.util.JsonSortUtil;
import com.raonsecure.odi.wallet.util.json.GsonWrapper;

public abstract class IWObject {
	
	public String toJson() {
		GsonWrapper gson = new GsonWrapper();
		String json = gson.toJson(this);
		return JsonSortUtil.sortJsonString(gson, json);
	}
	
	public abstract void fromJson(String val);	
}
