package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum DIDStatus {
	
	VALID("valid"), 
	PAUSED("paused"), 	
	REVOKED("revoked");																						// AUTHENTICATION

	private String status;

	DIDStatus(String status) {
		this.status = status;
	}

	public String getRawValue() {
		return status;
	}

	public static DIDStatus fromString(String text) {
		for (DIDStatus b : DIDStatus.values()) {
			if (b.status.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<DIDStatus> all() {
		return EnumSet.allOf(DIDStatus.class);
	}

	public static void main(String[] args) {
		EnumSet<DIDStatus> keyStatus = EnumSet.of(DIDStatus.VALID, DIDStatus.REVOKED);

		for (DIDStatus keyStatu :keyStatus) {
			System.out.println(keyStatu + ": " + keyStatu.getRawValue());
		}
		 DIDStatus status = DIDStatus.valueOf("valid");
	}
}
