package com.raonsecure.odi.agent.enums.vc;

import java.util.EnumSet;

public enum Type {
	VERIFIABLE_CREDENTIAL("VerifiableCredential"), 
	IDENTITY_CREDENTIAL("IdentityCredential"), 		
	OMNIONE_CERTIFICATE_CREDENTIAL("OmniOneCertificateCredential"), 	
	DAS_CERTIFICATE_CREDENTIAL("DasCertificateCredential"), 	
	ISSUER_CERTIFICATE_CREDENTIAL("IssuerCertificateCredential"), 	
	VERIFIER_CERTIFICATE_CREDENTIAL("VerifierCertificateCredential"), 	
	
	// working vc 추가 
	;																						

	private String rawValue;

	Type(String rawValue) {
		this.rawValue = rawValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	public static Type fromString(String text) {
		for (Type b : Type.values()) {
			if (b.rawValue.equalsIgnoreCase(text)) {
				return b;
			}
		}
		return null;
	}

	public static EnumSet<Type> all() {
		return EnumSet.allOf(Type.class);
	}

	public static void main(String[] args) {
		EnumSet<Type> types = EnumSet.of(Type.VERIFIABLE_CREDENTIAL, Type.IDENTITY_CREDENTIAL);

		for (Type type :types) {
			System.out.println(type + ": " + type.getRawValue());
		}
		Type type = Type.valueOf("IDENTITY_CREDENTIAL");
	}
}
