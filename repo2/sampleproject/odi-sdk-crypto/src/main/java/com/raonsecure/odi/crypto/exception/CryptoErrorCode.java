package com.raonsecure.odi.crypto.exception;

public enum CryptoErrorCode implements CryptoErrorCodeInterface{
	
	ERR_CODE_CRYPTOMANAGER_BASE("CM", ""),
	ERR_CODE_CRYPTOMANAGER_INVALID_ALGORITHM_TYPE(ERR_CODE_CRYPTOMANAGER_BASE, 		"1000",	"Algorithm type is invalid"), 
	ERR_CODE_CRYPTOMANAGER_GEN_RANDOM_KEY_FAIL(ERR_CODE_CRYPTOMANAGER_BASE, 		"1001",		"Failed to generate random key"),
	ERR_CODE_CRYPTOMANAGER_GEN_RANDOM_FAIL(ERR_CODE_CRYPTOMANAGER_BASE, 			"1002",		"Failed to generate random"),
	
	ERR_CODE_CRYPTOMANAGER_AES_ENCRYPT_FAIL(ERR_CODE_CRYPTOMANAGER_BASE, 			"1003", "AES Encryption is failed"),
	ERR_CODE_CRYPTOMANAGER_AES_DECRYPT_FAIL(ERR_CODE_CRYPTOMANAGER_BASE, 			"1004", "AES Decryption is failed"),
	ERR_CODE_CRYPTOMANAGER_INVALID_ENCODING_TYPE(ERR_CODE_CRYPTOMANAGER_BASE, 		"1005", "Encoding type is invalid"),
	ERR_CODE_CRYPTOMANAGER_INVALID_DECOGING_TYPE(ERR_CODE_CRYPTOMANAGER_BASE, 		"1006", "Decoding type is invalid"),
	
	ERR_CODE_CRYPTOMANAGER_OUT_OF_RANGE_VALUE(ERR_CODE_CRYPTOMANAGER_BASE, 			"1007", "Out of range value"),
	
	ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PUBLIC_KEY(ERR_CODE_CRYPTOMANAGER_BASE, 	"1008",		"PublicKey is invalid"), 
	ERR_CODE_CRYPTOMANAGER_ECIES_INVALID_PRIVATE_KEY(ERR_CODE_CRYPTOMANAGER_BASE, 	"1009",		"PrivateKey is invalid"),
	ERR_CODE_CRYPTOMANAGER_ECIES_GEN_SECRET_FAIL(ERR_CODE_CRYPTOMANAGER_BASE, 		"1010",		"Failed to generate shared secret"),
	;
	
	private String code;
	private String msg;

	private CryptoErrorCode(String code, String msg) {
		this.code = code;
		this.msg = msg;
	}
	private CryptoErrorCode(CryptoErrorCode errCodeKeymanagerKeyBase, String code, String msg) {
		this.code = errCodeKeymanagerKeyBase.getCode() + code;
		this.msg = msg;
	}

	@Override
	public String getCode() {
		return code;
	}
	
	@Override
	public String getMsg() {
		return msg;
	}
	
	public static CryptoErrorCodeInterface getEnumByCode(String code) {
		
		CryptoErrorCode agentTypes[] = CryptoErrorCode.values();
		for (CryptoErrorCode iwCode : agentTypes) {
			if(iwCode.getCode() == code){
				return iwCode;
			}
		}
		
		throw new AssertionError("Unknown Enum Code");

	}

}
