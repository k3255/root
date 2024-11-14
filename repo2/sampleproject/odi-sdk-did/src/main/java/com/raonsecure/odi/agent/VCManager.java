package com.raonsecure.odi.agent;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.did.PublicKey;
import com.raonsecure.odi.agent.data.param.IssueVcParam;
import com.raonsecure.odi.agent.data.rest.ClaimInfo;
import com.raonsecure.odi.agent.data.rest.ClaimsDef;
import com.raonsecure.odi.agent.data.rest.SignatureParams;
import com.raonsecure.odi.agent.data.rest.VcResult;
import com.raonsecure.odi.agent.data.vc.Attribute;
import com.raonsecure.odi.agent.data.vc.Claims;
import com.raonsecure.odi.agent.data.vc.CredentialSubject;
import com.raonsecure.odi.agent.data.vc.Extension;
import com.raonsecure.odi.agent.data.vc.Issuer;
import com.raonsecure.odi.agent.data.vc.Schema;
import com.raonsecure.odi.agent.data.vc.VerifiableCredential;
import com.raonsecure.odi.agent.enums.did.DIDMethodType;
import com.raonsecure.odi.agent.enums.did.KeyPurpose;
import com.raonsecure.odi.agent.enums.vc.AttributeType;
import com.raonsecure.odi.agent.enums.vc.Location;
import com.raonsecure.odi.agent.enums.vc.SubjectType;
import com.raonsecure.odi.agent.enums.vc.TextFormat;
import com.raonsecure.odi.agent.enums.vc.Type;
import com.raonsecure.odi.agent.exception.DIDManagerErrorCode;
import com.raonsecure.odi.agent.exception.DIDManagerException;
import com.raonsecure.odi.crypto.enums.DigestEnum;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.odi.crypto.util.HashGenerator;
import com.raonsecure.odi.crypto.util.MultiBase;
import com.raonsecure.oid.crypto.encoding.Base64;

public class VCManager {

	public VcResult issueVc(IssueVcParam vcParam, String userDid, SubjectType subjectType) throws DIDManagerException, CryptoException  {
		Issuer issuer = vcParam.getIssuer();
		Schema schema = vcParam.getSchema();
		DIDDocument issuerDocumnet = vcParam.getDidDocument();

		Map<String, ClaimInfo> issuerAddCalims = vcParam.getIssuerAddClaims();
		Map<String, ClaimInfo> issuerAddExtCalims = vcParam.getIssuerAddExtClaims();
		
		if (!issuer.getId().equals(issuerDocumnet.getId())) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VCMANAGER_NOT_MACTH_ISSUER_AND_SCHEMA_OWNER);
		}

		VerifiableCredential verifiableCredential = new VerifiableCredential();
		if (vcParam.getContext() != null && !vcParam.getContext().isEmpty()) {
			verifiableCredential.setContext(vcParam.getContext());
		} else {
			verifiableCredential.setContext();
		}
		verifiableCredential.setId(UUID.randomUUID().toString());
		verifiableCredential.setType(getTypeEnumList(subjectType));
		verifiableCredential.setIssuer(issuer);
		verifiableCredential.setIssuanceDate(vcParam.getIssuanceDate());
		verifiableCredential.setExpirationDate(vcParam.getExpirationDate());
		verifiableCredential.setEvidence(vcParam.getEvidence());
		
		// CredentialSubject 설정
		CredentialSubject credentialSubject = new CredentialSubject();	
		
		if (subjectType == SubjectType.DAS) {
			if (!issuer.getId().equals(userDid)) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VCMANAGER_INVALID_ISSUER);
			}
		}

		credentialSubject.setId(userDid);
		
		//  claims 설정 
		List<Claims> vcInnerClaims = new ArrayList<Claims>();

		for (ClaimsDef claimDef : schema.getClaimsDef()) {
			Claims claim = createClaims(claimDef, issuerAddCalims.get(claimDef.getCode()));
			vcInnerClaims.add(claim);
		}
		    
		if (!vcInnerClaims.isEmpty()) {
			credentialSubject.setClaims(vcInnerClaims);
		}
		verifiableCredential.setCredentialSubject(credentialSubject);
		
		checkClaims(credentialSubject.getClaims(), schema.getClaimsDef());

		
		Extension extension = new Extension();
		
		// extension - claims 설정
		List<Claims> extInnerClaims = new ArrayList<Claims>();
		if (issuerAddExtCalims != null && !issuerAddExtCalims.isEmpty()) {
			for (ClaimsDef claimDef : vcParam.getExtClaimsDef()) { // bc scheam
				Claims claim = createClaims(claimDef, issuerAddExtCalims.get(claimDef.getCode()));
				extInnerClaims.add(claim);
			}

			if (!extInnerClaims.isEmpty()) {
				extension.setClaims(extInnerClaims);
			}
			
			credentialSubject.setExtension(extension);
		}
	
		verifiableCredential.setEvidence(vcParam.getEvidence());
		if (subjectType == SubjectType.USER) {
			verifiableCredential.setEvidenceLevel(vcParam.getEvidenceLevel().getRawValue());
		}
		verifiableCredential.setSchema(getSchema(schema));

		PublicKey signPublicKey = getSignPublicKey(issuerDocumnet, vcParam.getAssertKeyId());
		verifiableCredential.setProof(null);

		List<SignatureParams> claimsSigParams = getClaimsDataToSign(verifiableCredential,
				signPublicKey, subjectType);

		List<SignatureParams> extClaimsSigParams = null;
		if (verifiableCredential.getCredentialSubject().getExtension() != null &&
				verifiableCredential.getCredentialSubject().getExtension().getClaims() !=null) {
			extClaimsSigParams = getExtClaimsDataToSign(verifiableCredential, signPublicKey);
		}

		VcResult vcResult = new VcResult();
		vcResult.setSubjectType(subjectType);
		vcResult.setVerifiableCredentialWithoutSign(verifiableCredential);
		vcResult.setClaimsSigParams(claimsSigParams);
		vcResult.setExtClaimsSigParams(extClaimsSigParams);

		return vcResult;
	}

	private PublicKey getSignPublicKey(DIDDocument issuerDocumnet, String assertkeyId) throws DIDManagerException {

		boolean isAssertmathod = issuerDocumnet.checkMethodType(issuerDocumnet.getId() + "#" + assertkeyId,
				DIDMethodType.ASSERTION_METHOD);
		if (!isAssertmathod) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VCMANAGER_NOT_ASSERTION_METHOD_TYPE);
		}

		PublicKey publicKey = issuerDocumnet.getPublicKey(issuerDocumnet.getId() + "#" + assertkeyId);
		return publicKey;

	}

	private boolean isDefaultAttribute(Attribute attribute) {

		if (!attribute.getType().equals(AttributeType.TEXT.getRawValue())) {
			return false;
		} else if (!attribute.getFormat().equals(TextFormat.PLAIN.getRawValue())) {
			return false;
		} else if (attribute.isHideValue()) {
			return false;
		} else if (!attribute.getLocation().equals(Location.INLINE.getRawValue())) {
			return false;
		}
		return true;
	}
	
	private List<SignatureParams> getExtClaimsDataToSign(VerifiableCredential verifiableCredential,
			PublicKey signPublicKey) {

		VerifiableCredential tmpVerifiableCredential = new VerifiableCredential();
		tmpVerifiableCredential.fromJson(verifiableCredential.toJson());

		// credentialSubject.claims 제거 하여 서명 생성
		tmpVerifiableCredential.getCredentialSubject().setClaims(null);
		tmpVerifiableCredential.getCredentialSubject().getExtension().setProof(null);

		tmpVerifiableCredential.setProof(null);

		List<Proof> proof = new ArrayList<Proof>();
		proof.add(getProofWithOutSign(verifiableCredential.getIssuanceDate(), signPublicKey.getId(),
				KeyPurpose.ASSERTION_METHOD));
		tmpVerifiableCredential.getCredentialSubject().getExtension().setProof(proof);

		List<SignatureParams> signatureParams = new ArrayList<SignatureParams>();
		SignatureParams signatureParam = new SignatureParams();
		signatureParam.setData(tmpVerifiableCredential.toJson());
		signatureParam.setKeyId(signPublicKey.getId().split("#")[1]);
		signatureParams.add(signatureParam);

		verifiableCredential.getCredentialSubject().getExtension().setProof(proof);
		return signatureParams;

	}

	private List<SignatureParams> getClaimsDataToSign(VerifiableCredential verifiableCredential,
			PublicKey signPublicKey, SubjectType subjectType) {

		VerifiableCredential tmpVerifiableCredential = new VerifiableCredential();
		tmpVerifiableCredential.fromJson(verifiableCredential.toJson());

		tmpVerifiableCredential.getCredentialSubject().setExtension(null);

		List<Proof> proof = new ArrayList<Proof>();
		proof.add(getProofWithOutSign(verifiableCredential.getIssuanceDate(), signPublicKey.getId(),
				KeyPurpose.ASSERTION_METHOD));
		tmpVerifiableCredential.setProof(proof);

		List<SignatureParams> signatureParams = new ArrayList<SignatureParams>();

		// 전체 서명 
		SignatureParams signatureParam = new SignatureParams();
		signatureParam.setData(tmpVerifiableCredential.toJson());
		signatureParam.setKeyId(signPublicKey.getId().split("#")[1]);
		signatureParams.add(signatureParam);

		// 개별 서명 
		if (subjectType == SubjectType.USER) {
			List<Claims> claims = tmpVerifiableCredential.getCredentialSubject().getClaims();

			for (Claims claim : claims) {
				List<Claims> claimsTemp = new ArrayList<Claims>();
				claimsTemp.add(claim);
				tmpVerifiableCredential.getCredentialSubject().setClaims(claimsTemp);

				signatureParam = new SignatureParams();
				signatureParam.setData(tmpVerifiableCredential.toJson());
				signatureParam.setKeyId(signPublicKey.getId().split("#")[1]);

				signatureParams.add(signatureParam);
			}
		}

		verifiableCredential.setProof(proof);
		return signatureParams;
	}

	private Proof getProofWithOutSign(String data, String didKeyId, KeyPurpose keyPurpose) {
		Proof proof = new Proof();
		proof.setCreated(data);
		proof.setProofPurpose(keyPurpose.getRawValue());
		proof.setVerificationMethod(didKeyId);

		return proof;
	}

	private void checkClaims(List<Claims> claims, List<ClaimsDef> claimsDef) throws DIDManagerException {

		for (ClaimsDef claimDef : claimsDef) {

			boolean isMandatory = claimDef.isMandatory();
			boolean check = claims.stream().anyMatch(claim -> claimDef.getCode().equals(claim.getCode()));

			if (isMandatory && !check) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VCMANAGER_NOT_SUBMITED_CLAIM,
						claimDef.getCode());
			}
		}
	}

	private Schema getSchema(Schema schema) {
		Schema ivcSchema = new Schema();
		ivcSchema.setId(schema.getId());
		ivcSchema.setName(schema.getName());
		ivcSchema.setVersion( schema.getVersion());
		return ivcSchema;
	}

	private List<String> getTypeEnumList(SubjectType subjectType) {
		List<String> credentialTypes = new ArrayList<>();
		credentialTypes.add(Type.VERIFIABLE_CREDENTIAL.getRawValue());

		switch (subjectType) {
		case USER:
			credentialTypes.add(Type.IDENTITY_CREDENTIAL.getRawValue());
			break;
		case DAS:
			credentialTypes.add(Type.OMNIONE_CERTIFICATE_CREDENTIAL.getRawValue());
			credentialTypes.add(Type.DAS_CERTIFICATE_CREDENTIAL.getRawValue());
			break;
		case ISSUER:
			credentialTypes.add(Type.OMNIONE_CERTIFICATE_CREDENTIAL.getRawValue());
			credentialTypes.add(Type.ISSUER_CERTIFICATE_CREDENTIAL.getRawValue());
			break;
		case VERIFIER:
			credentialTypes.add(Type.OMNIONE_CERTIFICATE_CREDENTIAL.getRawValue());
			credentialTypes.add(Type.VERIFIER_CERTIFICATE_CREDENTIAL.getRawValue());
			break;
		default:
			break;
		}

		return credentialTypes;
	}
	
	private Claims createClaims(ClaimsDef claimDef, ClaimInfo claimInfo) throws  CryptoException {
		if(claimInfo == null){
			return null; 
		}
		Claims claim =  new Claims();	
		claim.fromJson(claimDef.toJson());	
		
		Attribute attribute = claim.getAttribute();
		attribute.setFormat(claimInfo.getFormat());
		
		String value;
		if (attribute.getType().equals(AttributeType.TEXT.getRawValue())) {
			
		    value = (attribute.getFormat().equals(TextFormat.PLAIN.getRawValue()) 
		            && attribute.getLocation().equals(Location.INLINE.getRawValue())) ? claimInfo.getValue()
		            : MultiBase.encode(claimInfo.getValue().getBytes(StandardCharsets.UTF_8), MultiBaseEnum.getByCharacter(claimInfo.getEncodeType()));	
				// attach 에 대해서는 정의되면 분기문 추가 필요 	
		} else {
			byte[] byteValue = claimInfo.getValue() != null ? claimInfo.getValue().getBytes(StandardCharsets.UTF_8) : claimInfo.getByteValue();
			value = attribute.getLocation().equals(Location.ATTACH.getRawValue()) ? new String(byteValue, StandardCharsets.UTF_8) :
					MultiBase.encode(byteValue, MultiBaseEnum.getByCharacter(claimInfo.getEncodeType()));
				
			if (attribute.getLocation() != Location.INLINE.getRawValue()) {			
				byte[] digestValue = HashGenerator.generateHash(byteValue, DigestEnum.fromString(claimInfo.getDigestAlgoType()));
				String base64Value = Base64.encodeToString(digestValue, Base64.NO_WRAP);
				claim.setDigestSRI(claimInfo.getDigestAlgoType() + '-' + base64Value);
			}
		}
		
		claim.setValue(value); 
		
		if(isDefaultAttribute(attribute)) {
			claim.setAttribute(null);
		}
		
		return claim;
	}
}