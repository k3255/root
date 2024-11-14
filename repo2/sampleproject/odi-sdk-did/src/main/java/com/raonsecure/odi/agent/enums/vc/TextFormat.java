package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum TextFormat {
	PLAIN("plain"), HTML("html"), XML("xml"), CSV("csv");

	private String rawValue;

	TextFormat(String rawValue) {
		this.rawValue = rawValue;
	}


	public String getRawValue() {
		return rawValue;
	}
	
	public static TextFormat fromString(String text) {
		for (TextFormat b : TextFormat.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<TextFormat> all() {
		return EnumSet.allOf(TextFormat.class);
	}
	

}
