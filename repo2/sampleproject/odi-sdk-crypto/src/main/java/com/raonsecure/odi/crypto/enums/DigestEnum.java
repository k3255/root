package com.raonsecure.odi.crypto.enums;

import java.util.EnumSet;

public enum DigestEnum {

	Sha256("sha256"), Sha512("sha512"), Sha384("sha384");

	private String rawValue;

	DigestEnum(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	// default Sha384 or null .. 
	public static DigestEnum fromString(String text) {
		for (DigestEnum b : DigestEnum.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return Sha384;
	}

	public static EnumSet<DigestEnum> all() {
		return EnumSet.allOf(DigestEnum.class);
	}

}
