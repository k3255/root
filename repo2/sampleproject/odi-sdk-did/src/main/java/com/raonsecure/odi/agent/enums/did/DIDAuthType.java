package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum DIDAuthType {
	HOMEPAGE("homepage"), 
	CERTIFICATE("certificate");
																				
	

	private String serviceId;

	DIDAuthType(String serviceId) {
		this.serviceId = serviceId;
	}

	public String getRawValue() {
		return serviceId;
	}

	public static DIDAuthType fromString(String text) {
		for (DIDAuthType b : DIDAuthType.values()) {
			if (b.serviceId.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<DIDAuthType> all() {
		return EnumSet.allOf(DIDAuthType.class);
	}

	public static void main(String[] args) {
		EnumSet<DIDAuthType> serviceId = EnumSet.of(DIDAuthType.HOMEPAGE, DIDAuthType.CERTIFICATE);

		for (DIDAuthType id :serviceId) {
			System.out.println(id + ": " + id.getRawValue());
		}
		DIDAuthType id = DIDAuthType.valueOf("homepage");
	}
}
