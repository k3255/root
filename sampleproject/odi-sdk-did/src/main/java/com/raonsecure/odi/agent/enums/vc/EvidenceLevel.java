package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum EvidenceLevel {
	AL1("AL1"), 
	AL2("AL2"), 	
	AL3("AL3");																						// AUTHENTICATION

	private String rawValue;

	EvidenceLevel(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	public static EvidenceLevel fromString(String text) {
		for (EvidenceLevel b : EvidenceLevel.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<EvidenceLevel> all() {
		return EnumSet.allOf(EvidenceLevel.class);
	}

	public static void main(String[] args) {
		EnumSet<EvidenceLevel> evidenceLevels = EnumSet.of(EvidenceLevel.AL1, EvidenceLevel.AL2);

		for (EvidenceLevel evidenceLevel :evidenceLevels) {
			System.out.println(evidenceLevel + ": " + evidenceLevel.getRawValue());
		}
		EvidenceLevel evidenceLevel = EvidenceLevel.valueOf("AL1");
	}
}
