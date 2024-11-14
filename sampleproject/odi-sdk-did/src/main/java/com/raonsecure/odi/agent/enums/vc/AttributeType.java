package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum AttributeType {
	TEXT("text"), IMAGE("image"), DOCUMENT("document");

	private String rawValue;

	AttributeType(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}
	
	public static AttributeType fromString(String text) {
		for (AttributeType b : AttributeType.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<AttributeType> all() {
		return EnumSet.allOf(AttributeType.class);
	}

}
