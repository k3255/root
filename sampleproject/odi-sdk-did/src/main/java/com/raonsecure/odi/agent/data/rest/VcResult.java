package com.raonsecure.odi.agent.data.rest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.vc.Attribute;
import com.raonsecure.odi.agent.data.vc.Claims;
import com.raonsecure.odi.agent.data.vc.CredentialSubject;
import com.raonsecure.odi.agent.data.vc.Extension;
import com.raonsecure.odi.agent.data.vc.VerifiableCredential;
import com.raonsecure.odi.agent.data.vc.result.ClaimsResult;
import com.raonsecure.odi.agent.data.vc.result.CredentialSubjectResult;
import com.raonsecure.odi.agent.data.vc.result.VcClaimsResult;
import com.raonsecure.odi.agent.data.vp.VerifiablePresentation;
import com.raonsecure.odi.agent.enums.did.DIDKeyType;
import com.raonsecure.odi.agent.enums.vc.AttributeType;
import com.raonsecure.odi.agent.enums.vc.Location;
import com.raonsecure.odi.agent.enums.vc.Status;
import com.raonsecure.odi.agent.enums.vc.SubjectType;
import com.raonsecure.odi.agent.enums.vc.TextFormat;
import com.raonsecure.odi.agent.exception.DIDManagerErrorCode;
import com.raonsecure.odi.agent.exception.DIDManagerException;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VcResult {
	private String status;
	
	private List<SignatureParams> claimsSigParams;

	private List<SignatureParams> extClaimsSigParams;
	
	private VerifiableCredential verifiableCredentialWithoutSign;
	
	private VerifiableCredential verifiableCredential;
	
	private SubjectType subjectType; 
	
	private VerifiablePresentation verifiablePresentation;
	
	private List<SignatureParams> vpSigParamsToVerify; 
	
	private List<SignatureParams> claimsSigParamsToVerify; 
		
	private List<SignatureParams> extClaimsSigParamsToVerify; 
	
	public void setSignToExtClaims(List<SignatureParams> signatureParams) throws DIDManagerException {

		Optional<List<Proof>> proofOptional = Optional.ofNullable(verifiableCredentialWithoutSign)
				.map(vc -> vc.getCredentialSubject()).map(cs -> cs.getExtension()).map(ext -> ext.getProof());

		if (!proofOptional.isPresent()) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VCMANAGER_NOT_EXIST_PROOF);
		}

		Proof proof = proofOptional.get().get(0);

		for (int i = 0; i < signatureParams.size(); i++) {
			SignatureParams signatureParam = signatureParams.get(i);
			boolean firstIndex = i == 0 ? true : false;
			updateProofWithSignatureParams(proof, signatureParam, firstIndex);
		}

		if (this.verifiableCredential == null) {
			this.verifiableCredential = this.verifiableCredentialWithoutSign;
		}

		List<Proof> tmpProofs = new ArrayList<Proof>();
		tmpProofs.add(proof);
		
		
		this.verifiableCredential.getCredentialSubject().getExtension().setProof(tmpProofs);

	}
		
	public void setSignToClaims(List<SignatureParams> signatureParams) throws DIDManagerException {
		if (verifiableCredentialWithoutSign.getProof() != null) {
			Proof proof = verifiableCredentialWithoutSign.getProof().get(0);

			if (subjectType != SubjectType.USER) {
				updateProofWithSignatureParams(proof, signatureParams.get(0), true);
			} else {
				for (int i = 0; i < signatureParams.size(); i++) {
					SignatureParams signatureParam = signatureParams.get(i);
					boolean firstIndex = i == 0 ? true : false;
					updateProofWithSignatureParams(proof, signatureParam, firstIndex);
				}
			}
			if (this.verifiableCredential == null) {
				this.verifiableCredential = this.verifiableCredentialWithoutSign;
			}

			List<Proof> proofs = new ArrayList<>();
			proofs.add(proof);
			this.verifiableCredential.getProof().clear();
			this.verifiableCredential.setProof(proofs);
		}
	}

	
	
	private void updateProofWithSignatureParams(Proof proof, SignatureParams signatureParam, boolean firstIndex) throws DIDManagerException {

		validateKeyId(signatureParam.getKeyId(), proof);

		proof.setType(signatureParam.getAlgString() + DIDKeyType.VERIFICATIONKEY.getRawValue());
		if (firstIndex) {
			proof.setProofValue(signatureParam.getSignatureValue());
		} else {
			if(proof.getProofValueList() == null) {
				proof.setProofValueList(new ArrayList<String>());
			}		
			proof.getProofValueList().add(signatureParam.getSignatureValue());
		}
	}

	private void validateKeyId(String keyId, Proof proof) throws DIDManagerException {
	    if (!keyId.equals(proof.getVerificationMethod().split("#")[1])) {
	        // 예외 처리 로직 추가
	    	throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VCMANAGER_NOT_MACTH_SIGN_KEY_AND_PROOF_KEY);
	    }
	}
	
	
	public String getVcMetaData() {
		
		VcMeta vcMeta = new VcMeta();
		vcMeta.setId(this.verifiableCredential.getId());
		vcMeta.setIssuer(this.verifiableCredential.getIssuer());
		vcMeta.setSubjectId(this.verifiableCredential.getCredentialSubject().getId());
		vcMeta.setIssuanceDate(this.verifiableCredential.getIssuanceDate());
		vcMeta.setExpirationDate(this.verifiableCredential.getExpirationDate());
		vcMeta.setFormatVersion(this.verifiableCredential.getFormatVersion());
		vcMeta.setSchemaId(this.verifiableCredential.getSchema().getId());
		vcMeta.setStatus(Status.ACTIVE.toString());
		
		return vcMeta.toJson();
	}

	
	public VcClaimsResult getVcClaimsResult() {

		if (this.verifiablePresentation.getVerifiableCredential() == null) {
			return null;
		}

		VcClaimsResult vcClaimsResult = new VcClaimsResult();

		for (VerifiableCredential verifiableCredential : this.verifiablePresentation.getVerifiableCredential()) {
			CredentialSubjectResult credentialSubjectResult = new CredentialSubjectResult();

			CredentialSubject tmpCredentialSubject = new CredentialSubject();
			tmpCredentialSubject.fromJson(verifiableCredential.getCredentialSubject().toJson());

			verifiableCredential.setCredentialSubject(null);
			vcClaimsResult.fromJson(verifiableCredential.toJson());

			credentialSubjectResult.setId(tmpCredentialSubject.getId());

			List<ClaimsResult> claimsResult = new ArrayList<ClaimsResult>();
			claimsResult = getClaimsResult(tmpCredentialSubject);

			if (claimsResult != null && !claimsResult.isEmpty()) {
				credentialSubjectResult.setClaimsResult(claimsResult);
			}

			vcClaimsResult.setCredentialSubjectResult(credentialSubjectResult);
		}

		return vcClaimsResult;
	}
	

	private List<ClaimsResult> getClaimsResult(CredentialSubject credentialSubject) {
		List<ClaimsResult> claimsResult = new ArrayList<ClaimsResult>();

		List<Claims> claims = credentialSubject.getClaims();
		List<Claims> extClaims = Optional.ofNullable(credentialSubject.getExtension()).map(Extension::getClaims)
				.orElse(Collections.emptyList());


		if (claims != null && !claims.isEmpty()) {
			for (Claims claim : claims) {
				claimsResult.add(getClaimResult(claim));
			}
		}

		if (extClaims != null && !extClaims.isEmpty()) {
			for (Claims claim : extClaims) {
				claimsResult.add(getClaimResult(claim));
			}
		}

		return claimsResult;
	}
	
	private ClaimsResult getClaimResult(Claims claim) {
		ClaimsResult claimResult = new ClaimsResult();
		
		if (claim.getAttribute() == null) {
			claimResult.setType(AttributeType.TEXT.getRawValue());
			claimResult.setFormat(TextFormat.PLAIN.getRawValue());
			claimResult.setHideValue(false);
			claimResult.setLocation(Location.INLINE.getRawValue());
		} else {
			Attribute attribute = claim.getAttribute();
			claimResult.setType(attribute.getType());
			claimResult.setFormat(attribute.getFormat());
			claimResult.setHideValue(attribute.isHideValue());
			claimResult.setLocation(attribute.getLocation());
			claimResult.setDigestSRI(claim.getDigestSRI());
		}
		claimResult.setCode(claim.getCode());
		claimResult.setValue(claim.getValue());
		claimResult.setCaption(claim.getCaption());
		
		return claimResult;

	}

}
