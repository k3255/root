package com.raonsecure.odi.crypto.enums;

import com.raonsecure.odi.crypto.ec.CurveParam;
import com.raonsecure.odi.crypto.ec.EcTools;

public enum CurveParamEnum {
	
	SECP256_K1("Secp256k1", "K1", 0), SECP256_R1("Secp256r1", "R1", 1);

	private String value;

	private String prefix;

	private int number;

	private CurveParamEnum(String value, String prefix, int number) {
		this.value = value;
		this.prefix = prefix;
		this.number = number;
	}

	public String getValue() {
		return value;
	}

	public String getPrefix() {
		return prefix;
	}

	public int getNumber() {
		return number;
	}

	public CurveParam getCommandCurveParam() {
		return EcTools.getCurveParam(this.number);
	}
	
	public CurveParam getCommandCurveParam(int number) {
		return EcTools.getCurveParam(number);
	}

}
