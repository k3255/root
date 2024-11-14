package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum DIDKeyType {

	VERIFICATIONKEY("VerificationKey2018"), 
	KEYAGREEMENTKEY("KeyAgreementKey2019");

	private String keyType;

	DIDKeyType(String keyType) {
		this.keyType = keyType;
	}

	public String getRawValue() {
		return keyType;
	}

	public static DIDKeyType fromString(String rawlavue) {
		for (DIDKeyType b : DIDKeyType.values()) {
			if (b.keyType.equalsIgnoreCase(rawlavue)) {
				return b;
			}
		}
		return null;
	}
	
	public static EnumSet<DIDKeyType> all() {
		return EnumSet.allOf(DIDKeyType.class);
	}

	public static void main(String[] args) {
		EnumSet<DIDKeyType> keyType = EnumSet.of(DIDKeyType.VERIFICATIONKEY);

		for (DIDKeyType didKeyType :keyType) {
			System.out.println(didKeyType + ": " + didKeyType.getRawValue());
		}
	}
}
