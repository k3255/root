package com.raonsecure.odi.crypto.ecies;

import java.security.Security;


/**
 * 인터페이스 : Server 와 Client 가 함께 사용할 수 있는 서명 및 검증에 대한 interface를 정의
 * <pre>History:</b>
 *		Eliot, 2018.09.13 최초작성
 * </pre>
 *
 * @author Eliot
 * @version 1.0
 * @see None
 */




public abstract class CryptoHelperInterface {
	
	public static final String Provider_SC = "SC";
	
	static {
		Security.removeProvider(Provider_SC);
		Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
	}
}
