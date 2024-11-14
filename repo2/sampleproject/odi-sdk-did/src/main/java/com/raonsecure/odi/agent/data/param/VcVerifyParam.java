package com.raonsecure.odi.agent.data.param;

import java.util.List;

import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.vc.Condition;

import lombok.Getter;
import lombok.Setter;
@Getter
@Setter
public class VcVerifyParam {
	
	/**
	 *   vc  만료기한 검증 유무 
	 */
	private boolean checkVcExpirationDate = true;
	
	/**
	 *   필수 클레임 검증 유무
	 */
	//private boolean checkServiceCode = true;
	
	/**
	 *   service code - conditionList 
	 */
	private List<Condition> conditionList; 
	
	/**
	 *   user dids  
	 */
	private DIDDocument holderDIDDocument; 
	
	
	private DIDDocument issuerDIDDocument;
	
	public VcVerifyParam(List<Condition> conditionList, DIDDocument holderDIDDocument, DIDDocument issuerDIDDocument) {

		this.conditionList = conditionList;
		this.holderDIDDocument = holderDIDDocument;
		this.issuerDIDDocument = issuerDIDDocument;
	}

}
