package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum ServiceType {
	LINKED_DOMAINS("LinkedDomains"), 
	LINKED_DOCUMENT("LinkedDocument");
																				
	

	private String serviceType;

	ServiceType(String serviceType) {
		this.serviceType = serviceType;
	}

	public String getRawValue() {
		return serviceType;
	}

	public static ServiceType fromString(String text) {
		for (ServiceType b : ServiceType.values()) {
			if (b.serviceType.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<ServiceType> all() {
		return EnumSet.allOf(ServiceType.class);
	}

	public static void main(String[] args) {
		EnumSet<ServiceType> serviceType = EnumSet.of(ServiceType.LINKED_DOMAINS, ServiceType.LINKED_DOCUMENT);

		for (ServiceType type :serviceType) {
			System.out.println(type + ": " + type.getRawValue());
		}
		ServiceType type = ServiceType.valueOf("LinkedDomains");
	}
}
