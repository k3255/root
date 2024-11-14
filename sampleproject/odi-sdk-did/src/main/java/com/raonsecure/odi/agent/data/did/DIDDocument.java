package com.raonsecure.odi.agent.data.did;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.enums.did.DIDMethodType;
import com.raonsecure.odi.agent.util.GsonWrapper;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DIDDocument extends IWObject{
	@SerializedName("@context")
    @Expose
    private List<String> context;
		
    @SerializedName("id")
    @Expose
    private String id;
    
    @SerializedName("controller")
    @Expose
	private String controller;
	
	@SerializedName("verificationMethod")
	@Expose
	private List<PublicKey> verificationMethod;
	
	@SerializedName("assertionMethod")
	@Expose
	private List<String> assertionMethod;
	
	@SerializedName("authentication")
	@Expose
	private List<String> authentication;
	
	@SerializedName("keyAgreement")
	@Expose
	private List<String> keyAgreement;
	
	@SerializedName("capabilityInvocation")
	@Expose
	private List<String> capabilityInvocation;
	
	@SerializedName("capabilityDelegation:")
	@Expose
	private List<String> capabilityDelegation;
	
    @SerializedName("updated")
    @Expose
    private String updated;
    	
    @SerializedName("service")
    @Expose
    private List<Service> service;
    
    @SerializedName("proof")
    @Expose
    private List<Proof> proof;
        
	
	public DIDDocument() {	
	}
    
	public DIDDocument(String val) {
		fromJson(val);
	}
	
	public void setContext(String context){
		if (context != null) { 
			if(this.context == null) {
				this.context = new ArrayList<String>();		
			}
			this.context.add(context);
		}else {
			this.context = null; 
		}
	}

	public void setVerificationMethod(List<PublicKey> verificationMethods) {

		if (verificationMethods == null) {
			this.verificationMethod = null;
		} else {
			this.verificationMethod = new ArrayList<PublicKey>(verificationMethods);
		}
	}

	public void setVerificationMethod(PublicKey verificationMethod) {

		if (verificationMethod != null) {
			if (this.verificationMethod == null) {
				this.verificationMethod = new ArrayList<>();
			}
			this.verificationMethod.add(verificationMethod);
		}else {
			this.verificationMethod = null; 
		}

	}
	
	public void setAssertionMethod(List<String> ids) {
		  if (ids == null) {
		        this.assertionMethod = null;
		    } else {
		        this.assertionMethod = new ArrayList<>(ids);
		    }
	}
	
	public void setAssertionMethod(String id) {

		if (id != null) {
			if (this.assertionMethod == null) {
				this.assertionMethod = new ArrayList<String>();
			}
			this.assertionMethod.add(id);
		}else {
			this.assertionMethod = null; 
		}
	}
	
	public void setAuthentication(List<String> ids) {
		if (ids == null) {
			this.authentication = null;
		} else {
			this.authentication = new ArrayList<>(ids);
		}
	}
	
	
	public void setAuthentication(String id) {

		if (id != null) {
			if (this.authentication == null) {
				this.authentication = new ArrayList<String>();
			}
			this.authentication.add(id);
		}else {
			this.authentication = null; 
		}
	}
	
	public void setKeyAgreement(List<String> ids) {
		if (ids == null) {
			this.keyAgreement = null;
		} else {
			this.keyAgreement = new ArrayList<>(ids);
		}
	}
	
	public void setKeyAgreement(String id) {
		if (id != null) {
			if (this.keyAgreement == null) {
				this.keyAgreement = new ArrayList<String>();
			}
			this.keyAgreement.add(id);
		}else {
			this.keyAgreement = null; 
		}
	}
	
	public void setCapabilityInvocation(List<String> ids) {
		if (ids == null) {
			this.capabilityInvocation = null;
		} else {
			this.capabilityInvocation = new ArrayList<>(ids);
		}
	}
	
	public void setCapabilityInvocation(String id) {
		if (id != null) {
			if (this.capabilityInvocation == null) {
				capabilityInvocation = new ArrayList<String>();
			}
			capabilityInvocation.add(id);
		}else {
			this.capabilityInvocation = null; 
		}
	}
	
	
	public void setCapabilityDelegation(List<String> ids) {
		if (ids == null) {
			this.capabilityDelegation = null;
		} else {
			this.capabilityDelegation = new ArrayList<>(ids);
		}
	}
	
	
	public void setCapabilityDelegation(String id) {
		if (id != null) {
			if (this.capabilityDelegation == null) {
				this.capabilityDelegation = new ArrayList<String>();
			}
			this.capabilityDelegation.add(id);
		}else {
			this.capabilityDelegation = null; 
		}
	}

	public void setService(List<Service> service) {
		if (service != null && service.size() > 0) {
			if (this.service == null) {
				this.service = new ArrayList<Service>();
			}
			this.service.addAll(service);
		}else {
			this.service  = null; 
		}
	}


	public void setProof(List<Proof> proofs) {
		if (proofs != null && proofs.size() > 0) {
			if (this.proof == null) {
				this.proof = new ArrayList<Proof>();
			}
			this.getProof().clear();
			this.proof.addAll(proofs);
		}else {
			this.proof = null; 
		}
	}
	

	public void setProof(Proof proof) {
		if (proof != null ) {
			if (this.proof == null) {
				this.proof = new ArrayList<Proof>();
			}
			this.proof.add(proof);
		}else {
			this.proof = null; 
		}
	}
    
	public static final DateTimeFormatter DATE_FROMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

	public static String dateToString(ZonedDateTime date) {
		return DATE_FROMAT.format(date);
	}
	
	public static ZonedDateTime stringToDate(String date) {
		LocalDateTime parsedDateTime = LocalDateTime.parse(date);
		ZonedDateTime zonedDateTime = ZonedDateTime.of(parsedDateTime, ZoneOffset.UTC);
		return zonedDateTime;
	}
	
	public PublicKey getPublicKey(String didKeyId) {
		for (PublicKey publicKey : verificationMethod) {
			if (publicKey.getId().equals(didKeyId)) {
				return publicKey;
			}
		}
		return null;
	}
	

	public boolean checkMethodType(String didKeyId, DIDMethodType didMethodType) {
	  

	    switch (didMethodType) {
	        case ASSERTION_METHOD:
	            return this.getAssertionMethod().contains(didKeyId);
	        case AUTHENTICATION:
	            return this.getAuthentication().contains(didKeyId);
	        case KEY_AGREEMENT:
	            return this.getKeyAgreement().contains(didKeyId);
	        case CAPABILITY_INVOCATION:
	            return this.getCapabilityInvocation().contains(didKeyId);
	        case CAPABILITY_DELEGATION:
	            return this.getCapabilityDelegation().contains(didKeyId);
	        default:
	            return false;
	    }
	}
	
	@Override
    public void fromJson(String val) {
		// 비어 있는 값 파싱 에러 확인하기 
    	GsonWrapper gson = new GsonWrapper();
        DIDDocument data = gson.fromJson(val, DIDDocument.class);
        
        context = data.getContext();
        id = data.getId();
        controller = data.getController();
        verificationMethod = data.getVerificationMethod();
        assertionMethod = data.getAssertionMethod();
        authentication = data.getAuthentication();
        keyAgreement = data.getKeyAgreement();
        capabilityInvocation = data.getCapabilityInvocation();
        capabilityDelegation = data.getCapabilityDelegation();
    	service = data.getService();
    	proof = data.getProof();
    	updated = data.getUpdated();
//        if(!StringUtils.isEmpty(data.getUpdated())) {
//    		updated = data.getUpdated();
//    	}
    	
    	
    }

//	public void addToAsserionMethod(String publicKeyId) {
//		// TODO Auto-generated method stub
//		
//	}
	
//	public List<String> getKeyList(String da, List<KeyInfo> keyInfos, KeyPurpose targetPurpose){
//		List<String> keyList = new ArrayList<String>();
//		for (KeyInfo keyinfo : keyInfos) {
//			if(keyinfo.getMethodType()==targetPurpose) {
//				keyList.add(da+"#"+keyinfo.getKeyId());
//			}
//		}
//		return keyList;
//	}
	
	
//    public List<PublicKey> getVerificationMethod() {
//        return verificationMethod != null ? new ArrayList<>(verificationMethod) : null;
//    }



}
