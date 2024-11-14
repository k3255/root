package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum ServiceId {
	HOMEPAGE("homepage"), 
	CERTIFICATE("certificate");
																				
	

	private String serviceId;

	ServiceId(String serviceId) {
		this.serviceId = serviceId;
	}

	public String getRawValue() {
		return serviceId;
	}

	public static ServiceId fromString(String text) {
		for (ServiceId b : ServiceId.values()) {
			if (b.serviceId.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<ServiceId> all() {
		return EnumSet.allOf(ServiceId.class);
	}

	public static void main(String[] args) {
		EnumSet<ServiceId> serviceId = EnumSet.of(ServiceId.HOMEPAGE, ServiceId.CERTIFICATE);

		for (ServiceId id :serviceId) {
			System.out.println(id + ": " + id.getRawValue());
		}
		ServiceId id = ServiceId.valueOf("homepage");
	}
}
