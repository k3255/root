package com.raonsecure.odi.agent.enums.did;

import java.util.EnumSet;

public enum DIDMethodType {
	ASSERTION_METHOD("assertionMethod", 1 << 0), // 0001 - 1
	AUTHENTICATION("authentication", 1 << 1), // 0010 - 2
	KEY_AGREEMENT("keyAgreement", 1 << 2), // 0100 - 4
	CAPABILITY_INVOCATION("capabilityInvocation",1 << 3), // 1000 - 8
	CAPABILITY_DELEGATION("capabilityDelegation", 1 << 4); // 16

	private final String name;
	private int rawValue;

    DIDMethodType(String name, int rawValue) {
        this.name = name;
        this.rawValue = rawValue;
    }
    
    public String getName() {
        return name;
    }

	public int getRawValue() {
		return rawValue;
	}

	// test 필요 
    public static DIDMethodType fromRawValue(int rawValue) {
      //  System.out.println("fromRawValue: " + rawValue);
        for (DIDMethodType type : DIDMethodType.values()) {
            if (type.getRawValue() == rawValue) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid raw value: " + rawValue);
    }

	
	public static EnumSet<DIDMethodType> all() {
		return EnumSet.allOf(DIDMethodType.class);
	}

	public static void main(String[] args) {
		EnumSet<DIDMethodType> myDIDMethods = EnumSet.of(DIDMethodType.ASSERTION_METHOD, DIDMethodType.AUTHENTICATION);

		
		for (DIDMethodType method : myDIDMethods) {
			System.out.println(method + ": " + method.getRawValue());
		}
		
		for (DIDMethodType method : DIDMethodType.all()) {
			System.out.println(method + ": " + method.getRawValue());
		}
	}
}
