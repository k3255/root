package com.raonsecure.odi.wallet.exception;

public class IWException extends IWCommonException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 2584536544817080786L;

	public IWException(String code) {
		super(IWErrorCode.getEnumByCode(code));
	}
	
	public IWException(String code, String msg) {
		super(code, msg);
	}
	
	
	public IWException(String code, Throwable throwable)  {
		super(IWErrorCode.getEnumByCode(code), throwable);
	}
	
	public IWException(IWErrorCode iwErrorCode)  {
		super(iwErrorCode);
	}
	
	public IWException(IWErrorCode iwErrorCode, Throwable throwable)  {
		super(iwErrorCode, throwable);
	}


	public String getStatusCode() {
		return errorCode;
	}

	@Override
	public String getErrorCode(){		
		return errorCode;
	}

	@Override
	public String getErrorReason() {
		return errorReason;
	}
}
