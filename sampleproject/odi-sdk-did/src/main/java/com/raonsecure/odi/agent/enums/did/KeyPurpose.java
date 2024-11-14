package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum KeyPurpose {
	ASSERTION_METHOD("assertionMethod"), 
	AUTHENTICATION("authentication"), 	
	KEY_AGREEMENT("keyAgreement"),
	CAPABILITY_INVOCATION("capabilityInvocation"),
	CAPABILITY_DELEGATION("capabilityDelegation");
	
	private String purpose;

	KeyPurpose(String purpose) {
		this.purpose = purpose;
	}

	public String getRawValue() {
		return purpose;
	}

	public static KeyPurpose fromString(String text) {
		for (KeyPurpose b : KeyPurpose.values()) {
			if (b.purpose.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}
	public static EnumSet<KeyPurpose> all() {
		return EnumSet.allOf(KeyPurpose.class);
	}
	
	public static void main(String[] args) {
		EnumSet<KeyPurpose> keyPurpose = EnumSet.of(KeyPurpose.KEY_AGREEMENT,KeyPurpose.AUTHENTICATION );

		for (KeyPurpose purpose :keyPurpose) {
			System.out.println(purpose + ": " + purpose.getRawValue());
		}
	}
}
