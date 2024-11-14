package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum SubjectType {
	USER("User"), 
	DAS("Das"), 	
	ISSUER("Issuer"), 	
	VERIFIER("Verifier"), 	
	;																						

	private String rawValue;

	SubjectType(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	public static SubjectType fromString(String text) {
		for (SubjectType b : SubjectType.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<SubjectType> all() {
		return EnumSet.allOf(SubjectType.class);
	}

	public static void main(String[] args) {
		EnumSet<SubjectType> types = EnumSet.of(SubjectType.USER, SubjectType.DAS);

		for (SubjectType type :types) {
			System.out.println(type + ": " + type.getRawValue());
		}
		SubjectType type = SubjectType.valueOf("IDENTITY_CREDENTIAL");
	}
}
