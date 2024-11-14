package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum Location {
	INLINE("inline"), REMOTE("remote"), ATTACH("attach");

	private String rawValue;

	Location(String rawValue) {
		this.rawValue = rawValue;
	}


	public String getRawValue() {
		return rawValue;
	}
	
	public static Location fromString(String text) {
		for (Location b : Location.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<Location> all() {
		return EnumSet.allOf(Location.class);
	}
	

}
