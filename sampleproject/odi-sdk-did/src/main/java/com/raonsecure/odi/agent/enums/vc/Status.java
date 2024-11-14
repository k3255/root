package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum Status {
	ACTIVE("ACTIVE", 1),
	INACTIVE("INACTIVE", 0),
	REMOVE("REMOVE", -1);	
	
	
	private String name;
	private int rawValue;

	Status(String name, int rawValue) {
		this.name = name;
		this.rawValue = rawValue;
	}

	public int getRawValue() {
		return rawValue;
	}

	public static Status fromString(String text) {
		for (Status b : Status.values()) {
			if (b.name.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<Status> all() {
		return EnumSet.allOf(Status.class);
	}

	public static void main(String[] args) {
		EnumSet<Status> statusEnums = EnumSet.of(Status.ACTIVE, Status.REMOVE);

		for (Status status :statusEnums) {
			System.out.println(status + ": " + status.name());
		}
		Status status = Status.valueOf("ACTIVE");
	}
}
