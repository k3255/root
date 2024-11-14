package com.raonsecure.odi.crypto.exception;

public class CryptoException extends Exception{

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
	
	public CryptoException(CryptoErrorCodeInterface ErrorEnum) {
		super("ErrorCode: " + ErrorEnum.getCode() + ", Message: " + ErrorEnum.getMsg());
		this.errorCode = ErrorEnum.getCode();
		this.errorMsg = ErrorEnum.getMsg();
	}
	
	public CryptoException(CryptoErrorCodeInterface ErrorEnum, String errorReason) {
		super("ErrorCode: " + ErrorEnum.getCode() + ", Message: " + ErrorEnum.getMsg() + ", Reason: " + errorReason);
		this.errorCode = ErrorEnum.getCode();
		this.errorMsg = ErrorEnum.getMsg();
		this.errorReason = errorReason;
	}
	
	public CryptoException(String errorCode, String errorMsg) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
	}
	
	public CryptoException(String iwErrorCode, Throwable throwable)  {
		super(iwErrorCode, throwable);
	}

	
	public CryptoException(String errorCode, String errorMsg, String errorReason) {
		super("ErrorCode: " + errorCode + ", Message: " + errorMsg + ", Reason: " + errorReason);
		this.errorCode = errorCode;
		this.errorMsg = errorMsg;
		this.errorReason = errorReason;
	}
	
	public CryptoException(CryptoErrorCode errorCode, Throwable throwable) {
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
