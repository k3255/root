package com.raonsecure.odi.agent.exception;

public class DIDManagerException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 6285544788893947401L;
	
	/**
	 * Error Code - int 범위에서 사용하셔야 합니다.
	 */
	protected String errorCode;

	/**
	 * Error 코드 메시지
	 */
	protected String errorMsg;

	/**
	 * Error 발생 사유
	 */
	protected String errorReason;
	
	public DIDManagerException(ErrorCodeInterface ErrorEnum) {
		super("ErrorCode: " + ErrorEnum.getCode() + ", Message: " + ErrorEnum.getMsg());
		this.errorCode = ErrorEnum.getCode();
		this.errorMsg = ErrorEnum.getMsg();
	}
	
	public DIDManagerException(ErrorCodeInterface ErrorEnum, String errorReason) {
		super("ErrorCode: " + ErrorEnum.getCode() + ", Message: " + ErrorEnum.getMsg() + ", Reason: " + errorReason);
		this.errorCode = ErrorEnum.getCode();
		this.errorMsg = ErrorEnum.getMsg();
		this.errorReason = errorReason;
	}
	
	public DIDManagerException(String errorCode, String errorMsg) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
	}
	
	public DIDManagerException(String iwErrorCode, Throwable throwable)  {
		super(iwErrorCode, throwable);
	}

	
	public DIDManagerException(String errorCode, String errorMsg, String errorReason) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg + ", Reason: " + errorReason);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
		this.errorReason = errorReason;
	}
	
	public DIDManagerException(DIDManagerErrorCode errorCode, Throwable throwable) {
		super("ErrorCode: " + errorCode +  ", Reason: " + throwable);
		this.errorCode = errorCode.getCode();
		this.errorMsg = errorCode.getMsg();
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getErrorReason() {
		return errorReason;
	}

	public String getErrorMsg() {
		return errorMsg;
	}
}
