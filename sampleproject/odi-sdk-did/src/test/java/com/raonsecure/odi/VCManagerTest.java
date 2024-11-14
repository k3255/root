package com.raonsecure.odi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.raonsecure.odi.agent.VCManager;
import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.param.IssueVcParam;
import com.raonsecure.odi.agent.data.rest.ClaimInfo;
import com.raonsecure.odi.agent.data.rest.ClaimsDef;
import com.raonsecure.odi.agent.data.rest.SignatureParams;
import com.raonsecure.odi.agent.data.rest.VcResult;
import com.raonsecure.odi.agent.data.vc.Attribute;
import com.raonsecure.odi.agent.data.vc.Evidence;
import com.raonsecure.odi.agent.data.vc.Issuer;
import com.raonsecure.odi.agent.data.vc.Schema;
import com.raonsecure.odi.agent.enums.vc.EvidenceLevel;
import com.raonsecure.odi.agent.enums.vc.SubjectType;
import com.raonsecure.odi.agent.exception.DIDManagerException;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;


public class VCManagerTest {
	
	public static VcResult holderVcResult;
	@DisplayName("issue vc")
	@Test
	public void issueVcForHolder() throws DIDManagerException, CryptoException {
		String schemaStr = "{\"claims\":[{\"attribute\":{\"hideValue\":true,\"location\":\"inline\",\"type\":\"text\"},\"caption\":\"이름\",\"code\":\"das.v1.name\",\"mandatory\":true},"
				+ "{\"attribute\":{\"hideValue\":true,\"location\":\"remote\",\"type\":\"text\"},\"caption\":\"url\",\"code\":\"das.v1.url\",\"mandatory\":true}],\"id\":\"issuer.schema\",\"name\":\"test schema\",\"version\":\"1.0\"}";
			
		String issuerDidsJson = "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"assertionMethod\":[\"did:omn:issuer#assert1\"],\"authentication\":[\"did:omn:issuer#auth1\"],\"capabilityInvocation\":[\"did:omn:issuer#invoke\"],\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer\",\"keyAgreement\":[\"did:omn:issuer#keyagree\"],\"updated\":\"2024-01-08T02:20:25\",\"verificationMethod\":[{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#assert1\",\"publicKeyMultibase\":\"zf7v4m3HJBoNHfMw1Gjn24Sz8eP88EUJeCNZbvWKXHDQg\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#auth1\",\"publicKeyMultibase\":\"zfgCVCvkaNTunJ9WpYAW271AXFRMMs7wyqstrqw75eEJd\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#keyagree\",\"publicKeyMultibase\":\"z27XTBXV64KLUJP4G2q8Lcd7G1315DLCyE9puc58K8HYQg\",\"status\":\"valid\",\"type\":\"Secp256r1KeyAgreementKey2019\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#invoke\",\"publicKeyMultibase\":\"z23oDE9R9MAZxTrqvemm4YBGsEDhSfTvaW6baqtKmjLdAm\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"}]}";		
		DIDDocument issuerDids = new DIDDocument(issuerDidsJson);
	
		Schema schema = new Schema(schemaStr);
		schema.setId("default schema");
		Map<String, ClaimInfo>  privacy = new HashMap<String, ClaimInfo>();
		
		 ClaimInfo claimValue = new ClaimInfo();
		 claimValue.setCode("das.v1.name");
		 claimValue.setValue("함초롬");
		// claimValue.setEncodeType("u");
		 claimValue.setFormat("plain");

		 
			
		 ClaimInfo claimValue2 = new ClaimInfo();
		 claimValue2.setCode("das.v1.url");
		 String url = "http://192.168.0.86/odi";
		 claimValue2.setValue(url);
		 claimValue2.setEncodeType(MultiBaseEnum.Base64url.getCharacter());
		 claimValue2.setFormat("plain");
		
		
		 privacy.put(claimValue.getCode(), claimValue);
		 privacy.put(claimValue2.getCode(), claimValue2);
		

		// 블록체인에서 조회할  issuer 정보
		Issuer issuer = new Issuer();
		issuer.setId(issuerDids.getId());
		issuer.setName("issuer name");

		IssueVcParam issueVcParam = new IssueVcParam(schema, issuer, issuerDids, "assert1");

		// claims 설정 
		issueVcParam.setIssuerAddClaims(privacy);

		//  ext claims 
		List<ClaimsDef> extClaimsDef = new ArrayList<ClaimsDef>();
	
		ClaimsDef extClaimDef = new ClaimsDef();
		Attribute attb = new Attribute();
		attb.setType("text");
		attb.setLocation("inline");
		extClaimDef.setAttribute(attb);
		extClaimDef.setCode("issuer.nickname");
		extClaimDef.setCaption("닉네임");
	
		
		extClaimsDef.add(extClaimDef);
		issueVcParam.setExtClaimsDef(extClaimsDef);
		
		// ext 개인 정보 설정 
		 ClaimInfo extClaimValue = new ClaimInfo();
		 extClaimValue.setCode("issuer.nickname");
		 extClaimValue.setValue("보니는천재");
		 extClaimValue.setEncodeType("u");
		 extClaimValue.setFormat("plain");
		 
		Map<String, ClaimInfo>  extPrivacy = new HashMap<String, ClaimInfo>();
		extPrivacy.put(extClaimValue.getCode(), extClaimValue);
		issueVcParam.setIssuerAddExtClaims(extPrivacy);
		
		
		// 인증레벨 설정 
		issueVcParam.setEvidenceLevel(EvidenceLevel.AL1);
		
		// evidence 설정 
		 Evidence evidence = new Evidence();
		 evidence.setDocumentPresence("Digital");
		 evidence.setEvidenceDocument("k1");
		 evidence.setSubjectPresence("Digital");
		 evidence.setType(new ArrayList<String>(List.of("DocumentVerification")));
		 evidence.setVerifier(issuer.getId());
		
		 List<Evidence> evidenceList = new ArrayList<Evidence>();
		 evidenceList.add(evidence);
		 issueVcParam.setEvidence(evidenceList);

		VCManager vcManager = new VCManager();
		holderVcResult = vcManager.issueVc(issueVcParam, "did:omn:holder" , SubjectType.USER);
		
		System.out.println("1. issue vc :::");
		System.out.println("vc	: " + holderVcResult.getVerifiableCredentialWithoutSign().toJson());
		System.out.println("");
		getSignData(holderVcResult);
	}
	

	private void getSignData(VcResult vcResult) throws DIDManagerException, CryptoException {
		List<SignatureParams>  signatureParams = vcResult.getClaimsSigParams();
		System.out.println("2. getClaimsSigParams :::");
		
		for(SignatureParams signatureParam : signatureParams) {
			System.out.println("data	: " + signatureParam.getData());
			System.out.println("keyId	: " + signatureParam.getKeyId());
			System.out.println("");
		}
		
		List<SignatureParams>  extSignatureParams = vcResult.getExtClaimsSigParams();
		System.out.println("3. extSignatureParams :::");
		
		for(SignatureParams extsignatureParam : extSignatureParams) {
			System.out.println("data	: " + extsignatureParam.getData());
			System.out.println("keyId	: " + extsignatureParam.getKeyId());
		}
	}
}
