package com.raonsecure.odi.agent.exception;

public enum DIDManagerErrorCode implements ErrorCodeInterface{

	ERR_CODE_DIDMANAGER_BASE("DM", ""),
	ERR_CODE_DIDMANAGER_ADD_KEY_FAIL(ERR_CODE_DIDMANAGER_BASE, 	"1000",	"add key fail"),
	ERR_CODE_DIDMANAGER_UNSPECIFIED_METHOD(ERR_CODE_DIDMANAGER_BASE, 	"1001",	"unspecifiedMethod"),
	ERR_CODE_DIDMANAGER_WRONG_METHOD(ERR_CODE_DIDMANAGER_BASE, 	"1002",	"wrongMethod"),
	ERR_CODE_DIDMANAGER_DUPLICATED_KEY(ERR_CODE_DIDMANAGER_BASE, 	"1003",	"duplicatedKey"),
	ERR_CODE_DIDMANAGER_INVALID_METHODNAME(ERR_CODE_DIDMANAGER_BASE, 	"1004",	"Method name must be lower case alphanumeric (colon accepted) and have range between from 1 to 20 length"),
	ERR_CODE_DIDMANAGER_UNREGISTERED_KEY(ERR_CODE_DIDMANAGER_BASE, 	"1005",	"unregisteredKey"),
	ERR_CODE_DIDMANAGER_NOT_LINKED_KEY(ERR_CODE_DIDMANAGER_BASE, "1006","notLinkedKey" ),
	ERR_CODE_DIDMANAGER_EMPTY_LINKED_LIST(ERR_CODE_DIDMANAGER_BASE, "1007", "Linked list is empty" ),
	ERR_CODE_DIDMANAGER_EXIST_SERVICE_TYPE(ERR_CODE_DIDMANAGER_BASE, "1008", "This service type already exists" ),
	ERR_CODE_DIDMANAGER_NOT_A_SIGNING_KEY(ERR_CODE_DIDMANAGER_BASE, "1009", "It's not a signing key" ),
	ERR_CODE_DIDMANAGER_DA_IS_NULL(ERR_CODE_DIDMANAGER_BASE, "1010", "DA is null" ),
	ERR_CODE_DIDMANAGER_INSUFFICIENT_INFOS(ERR_CODE_DIDMANAGER_BASE, "1011", "There is empty field on KeyInfo" ),
	ERR_CODE_DIDMANAGER_NOT_EXIST_SIGNING_KEY(ERR_CODE_DIDMANAGER_BASE, "1012", "Signkey does not exist in DIDs"),
	ERR_CODE_DIDMANAGER_FILE_NOT_EXIST(ERR_CODE_DIDMANAGER_BASE, 	 "1013", "Document file does not exist"),


	ERR_CODE_VCMANAGER_BASE("VM", ""),
	ERR_CODE_VCMANAGER_NOT_MACTH_ISSUER_AND_SCHEMA_OWNER(ERR_CODE_VCMANAGER_BASE, 	"2000",	"The issuer and schema owner is not matched"),
	ERR_CODE_VCMANAGER_INVALID_ISSUER(ERR_CODE_VCMANAGER_BASE, 	"2001",	"DAS IVC can only be issued by DAS."),
	ERR_CODE_VCMANAGER_NOT_SUBMITED_CLAIM(ERR_CODE_VCMANAGER_BASE, 	"2002",	"Public claim is not submited"),
	ERR_CODE_VCMANAGER_NOT_ASSERTION_METHOD_TYPE(ERR_CODE_VCMANAGER_BASE, 	"2003",	"SignKey is not of type Assertion Method"),
	ERR_CODE_VCMANAGER_NOT_MACTH_SIGN_KEY_AND_PROOF_KEY(ERR_CODE_VCMANAGER_BASE, 	"2004",	"SignKey and key of proof are different"),
	ERR_CODE_VCMANAGER_NOT_EXIST_PROOF(ERR_CODE_VCMANAGER_BASE, 	"2005",	"Proof does not exist"),

	ERR_CODE_VPMANAGER_BASE("VM", ""),
	ERR_CODE_VPMANAGER_EXPIRED_VP(ERR_CODE_VPMANAGER_BASE, 	"3000",	"Expired Verifiable Presentation"),
	ERR_CODE_VPMANAGER_DELEGATED_VP(ERR_CODE_VPMANAGER_BASE, 	"3001",	"DIDs owner and VC owner are different"),
	ERR_CODE_VPMANAGER_EMPTY_CONDITIONLIST(ERR_CODE_VPMANAGER_BASE, 	"3002",	"Condition List is Empty"),
	ERR_CODE_VPMANAGER_NOT_ALLOW_SCHEMA(ERR_CODE_VPMANAGER_BASE, 	"3003",	"This Schema Id is not allowed"),
	ERR_CODE_VPMANAGER_PRIVACY_NOT_EXIST(ERR_CODE_VPMANAGER_BASE, 	"3004",	"Privacy Data does not Exist"),
	ERR_CODE_VPMANAGER_NOT_ALLOW_AL(ERR_CODE_VPMANAGER_BASE, 	"3005",	"This Evidence Level is not allowed"),
	ERR_CODE_VPMANAGER_NOT_ALLOW_ISSUER(ERR_CODE_VPMANAGER_BASE, 	"3006",	"This Issuer is not allowed"),
	ERR_CODE_VPMANAGER_NOT_CONTAIN_CLAIM(ERR_CODE_VPMANAGER_BASE, 	"3007",	"Requried Claim is not Submited"),
	ERR_CODE_VPMANAGER_EXPIRED_VC(ERR_CODE_VPMANAGER_BASE, 	"3008",	"Expired Verifiable Credential"),
	;
	private String code;
	private String msg;

	private DIDManagerErrorCode(String code, String msg) {
		this.code = code;
		this.msg = msg;
	}
	private DIDManagerErrorCode(DIDManagerErrorCode errCodeKeymanagerKeyBase, String subCode, String msg) {
		this.code = errCodeKeymanagerKeyBase.getCode() + subCode;
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

	public static ErrorCodeInterface getEnumByCode(int code) {

		DIDManagerErrorCode agentTypes[] = DIDManagerErrorCode.values();
		for (DIDManagerErrorCode iwCode : agentTypes) {
			if(iwCode.getCode().equals(code)){
				return iwCode;
			}
		}

		throw new AssertionError("Unknown Enum Code");

	}

}
