package com.raonsecure.odi.agent.data.param;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.rest.ClaimInfo;
import com.raonsecure.odi.agent.data.rest.ClaimsDef;
import com.raonsecure.odi.agent.data.vc.Evidence;
import com.raonsecure.odi.agent.data.vc.Issuer;
import com.raonsecure.odi.agent.data.vc.Schema;
import com.raonsecure.odi.agent.data.vc.VerifiableCredential;
import com.raonsecure.odi.agent.enums.vc.EvidenceLevel;

import lombok.Getter;
import lombok.Setter;

/**
 * VC 발급 초기 데이터
 * 
 * @author crham
 *
 */

@Getter
@Setter
public class IssueVcParam {

	/**
	 * Schema
	 */
	private Schema schema;

	/**
	 * Issuer
	 */
	private Issuer issuer;

	/**
	 * Issuer DIDDocument
	 */
	private DIDDocument didDocument;

	/**
	 * default 만료날짜
	 */
	private String expirationDate = "9999-12-31T23:59:59";
	/**
	 * 발급날짜
	 */
	private ZonedDateTime issuanceDate = ZonedDateTime.now(ZoneOffset.UTC);

	/**
	 * 서버 설정 개인 정보
	 */
	private Map<String,ClaimInfo> issuerAddClaims;

	/**
	 * issuer claims 정의 
	 */
	private List<ClaimsDef> extClaimsDef;
	
	/**
	 * 서버 설정 extension 개인 정보
	 */
	private Map<String,ClaimInfo>issuerAddExtClaims;

	private List<Evidence> evidence;

	private EvidenceLevel evidenceLevel;
	
	private List<String> context; 
	
    private String assertKeyId;
	
	/**
	 * Schema schema - schema info 
	 * Issuer issuer - issuer info 
	 * DIDDocument didDocument - issuer diddoc
	 */
	public IssueVcParam(Schema schema, Issuer issuer, DIDDocument didDocument, String assertKeyId) {
		this.schema = schema;
		this.issuer = issuer;
		this.didDocument = didDocument;
		this.assertKeyId = assertKeyId;
	}

	public String setExpiresTimeFromCurrentTime(Long millisecondsToAdd) {
		// 1밀리초 = 1000000 나노초
		ZonedDateTime expiresTime = issuanceDate.plusNanos(millisecondsToAdd * 1000000);
		expirationDate = dateToString(expiresTime);
		return expirationDate;
	}

	public void setExpiresDayFromCurrentTime(int daysToAdd) {
		ZonedDateTime expiresDay = issuanceDate.plusDays(daysToAdd);
		ZonedDateTime expiresTime = expiresDay.withHour(23).withMinute(59).withSecond(59).withNano(999 * 1000000);

		expirationDate = dateToString(expiresTime);
		
	//	return expirationDate;

	}

	// zoneId 설정 추가 필요 .. 
	public static String dateToString(ZonedDateTime date) {

		return VerifiableCredential.DATE_FROMAT.format(date);
	}

}
