package com.raonsecure.odi.wallet.exception;

public enum IWErrorCode implements IWErrorEnumInterface {
	ERR_CODE_KEYMANAGER_BASE("KM", ""),
	ERR_CODE_CRYPTOHELPER_ENCRYPT(ERR_CODE_KEYMANAGER_BASE, 	"1000",  "Failed to encrypt"),
	ERR_CODE_CRYPTOHELPER_DECRYPT(ERR_CODE_KEYMANAGER_BASE, 	"1001", 	"Failed to decrypt"),
	ERR_CODE_CRYPTOHELPER_GENSRANDOM_FAIL(ERR_CODE_KEYMANAGER_BASE, "1002", "Failed to generate random byte"),


	ERR_CODE_KEYMANAGER_DISCONNECT(ERR_CODE_KEYMANAGER_BASE, 						"1010", "KeyManager is disonnected"),
	ERR_CODE_KEYMANAGER_FILE_LOAD_FAIL(ERR_CODE_KEYMANAGER_BASE, 					"1011", "Failed to load the WalletFile"),
	ERR_CODE_KEYMANAGER_FILE_WRITE_FAIL(ERR_CODE_KEYMANAGER_BASE, 					"1012", "Failed to write the WalletFile"),
	ERR_CODE_KEYMANAGER_DUPLICATED_VC_ID(ERR_CODE_KEYMANAGER_BASE,  		"1013", "VC Id is duplicated"),

	ERR_CODE_KEYMANAGER_KEYID_NOT_EXIST(ERR_CODE_KEYMANAGER_BASE, "1020", "The keyId does not exist"),
	ERR_CODE_KEYMANAGER_KEYID_ALREADY_EXIST(ERR_CODE_KEYMANAGER_BASE, "1021", "The KeyId is already existed"),
	ERR_CODE_KEYMANAGER_KEYID_EMPTY_NAME(ERR_CODE_KEYMANAGER_BASE, "1022", "The Name for KeyId is empty"),
	ERR_CODE_KEYMANAGER_INVALID_ALGORITHM_TYPE(ERR_CODE_KEYMANAGER_BASE, "1023",	"Algorithm type is invalid"),
	ERR_CODE_KEYMANAGER_INVALID_KEYID_NAME(ERR_CODE_KEYMANAGER_BASE, "1024",	"The Name for KeyId must only be alphaNumeric"),
	ERR_CODE_KEYMANAGER_IWKEY_IS_NULL (ERR_CODE_KEYMANAGER_BASE, "1025",	"IWKey is null"),
	ERR_CODE_KEYMANAGER_INVALID_PRIVATE_KEY (ERR_CODE_KEYMANAGER_BASE, "1026",	"Invalid PrivateKey"),
	ERR_CODE_KEYMANAGER_INVALID_PUBLIC_KEY (ERR_CODE_KEYMANAGER_BASE, "1027",	"Invalid PublicKey"),
	ERR_CODE_KEYMANAGER_KEYINFO_EMPTY(ERR_CODE_KEYMANAGER_BASE, "1028",  "KeyInfo is empty"),



	ERR_CODE_KEYMANAGER_PASSWORD_NOT_SET(ERR_CODE_KEYMANAGER_BASE, "1030",	"The password does not set"),
	ERR_CODE_KEYMANAGER_PASSWORD_NOT_MATCH_WITH_THE_SET_ONE(ERR_CODE_KEYMANAGER_BASE, "1031",	"The password does not match with the set one"),
	ERR_CODE_KEYMANAGER_INVALID_PASSWORD(ERR_CODE_KEYMANAGER_BASE, "1032",	"The password is(are) invalid for use"),
	ERR_CODE_KEYMANAGER_PASSWORD_SAME_AS_OLD(ERR_CODE_KEYMANAGER_BASE, "1033",	"New password is the same as the old one"),


	ERR_CODE_KEYMANAGER_AES_ENCRYPT_FAIL(ERR_CODE_KEYMANAGER_BASE, "1040", "AES Encryption is failed"),
	ERR_CODE_KEYMANAGER_AES_DECRYPT_FAIL(ERR_CODE_KEYMANAGER_BASE, "1041", "AES Decryption is failed"),
	ERR_CODE_KEYMANAGER_ECIES_GEN_SECRET_FAIL(ERR_CODE_KEYMANAGER_BASE, 			"1042",	"Failed to generate shared secret"),




	ERR_CODE_KEYMANAGER_VERIFY_SIGN_FAIL(ERR_CODE_KEYMANAGER_BASE, "1050", "Verify signature is failed"),
	ERR_CODE_KEYMANAGER_INVALID_SIGN_VALUE(ERR_CODE_KEYMANAGER_BASE, "1051", "Sign value is invalid"),
	ERR_CODE_KEYMANAGER_NOT_FIND_RECID(ERR_CODE_KEYMANAGER_BASE, "1052", "could not find recid."),
	ERR_CODE_KEYMANAGER_FAIL_CONVERT_EOSTYPE(ERR_CODE_KEYMANAGER_BASE, "1053", "fail convert sign data to eostype."),
	ERR_CODE_KEYMANAGER_INVALID_R_S_VALUE(ERR_CODE_KEYMANAGER_BASE, "1054", "The r value must be 32 bytes."),


	ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_KEYGEN_FAIL(ERR_CODE_KEYMANAGER_BASE, "1060",	"Key generation in DefaultKeyStore is fail"),
	ERR_CODE_KEYMANAGER_DEFAULTKEYSTORE_AUTHENTICATE_FAIL(ERR_CODE_KEYMANAGER_BASE, "1061",		"Authenticating in DefaultKeyStore is fail"),

	ERR_CODE_DIDMANAGER_INVALID_METHODNAME(ERR_CODE_KEYMANAGER_BASE, "1070", "Method name must be lower case alphanumeric (colon accepted) and have range between from 1 to 20 length"),

	ERR_CODE_DIDMANAGER_ADD_KEY_FAIL(ERR_CODE_KEYMANAGER_BASE, "1080",	"Failed to add the key"),
	;

	private String code;
	private String msg;

	private IWErrorCode(String code, String msg) {
		this.msg = msg;
		this.code = code;
	}

	private IWErrorCode(IWErrorCode parentCode, String addCode, String msg) {
		this.msg = msg;
		this.code = parentCode.getCode() + addCode;
	}

	@Override
	public String getMsg() {
		return msg;
	}

	@Override
	public String getCode() {
		return code;
	}

	public static IWErrorEnumInterface getEnumByCode(String code) {

		IWErrorCode agentTypes[] = IWErrorCode.values();
		for (IWErrorCode iwCode : agentTypes) {
			if(iwCode.getCode() == code){
				return iwCode;
			}
		}

		throw new AssertionError("Unknown Enum Code");

	}

}
