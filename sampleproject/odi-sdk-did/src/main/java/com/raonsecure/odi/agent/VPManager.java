package com.raonsecure.odi.agent;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.raonsecure.odi.agent.data.Claim;
import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.did.PublicKey;
import com.raonsecure.odi.agent.data.param.VcVerifyParam;
import com.raonsecure.odi.agent.data.rest.SignatureParams;
import com.raonsecure.odi.agent.data.rest.VcResult;
import com.raonsecure.odi.agent.data.vc.Claims;
import com.raonsecure.odi.agent.data.vc.Condition;
import com.raonsecure.odi.agent.data.vc.CredentialSubject;
import com.raonsecure.odi.agent.data.vc.Extension;
import com.raonsecure.odi.agent.data.vc.Filter;
import com.raonsecure.odi.agent.data.vc.VerifiableCredential;
import com.raonsecure.odi.agent.data.vp.VerifiablePresentation;
import com.raonsecure.odi.agent.exception.DIDManagerErrorCode;
import com.raonsecure.odi.agent.exception.DIDManagerException;

import javax.net.ssl.KeyManager;

public class VPManager {
	
	public VerifiablePresentation makePresentation(List<VerifiableCredential> vcList, String expirationDate) throws Exception{

		// credentialId와 일치하는 vc 조회 테스트 시 생략
		/*
		List<VerifiableCredential> filteredByRequestInfo = new ArrayList<>();

		for(int i=0; i<1; i++){
			String credentialId = requestList.get(i).getCredentialId();
			List<Claim> publicClaims = requestList.get(i).getClaims();

			for(VerifiableCredential vc : vcList){
				if(vc.getId().equals(credentialId)){

					// claim 설정
					CredentialSubject credentialSubject = vc.getCredentialSubject();

					List<Claim> vcClaimList = null;//credentialSubject.getPublicClaims();
					List<Claim> newVcClaimList = new ArrayList<>();

					List<Proof> proof = vc.getProof();
					List<Proof> newProof = new ArrayList<Proof>();

					for (int index = 0; index < vcClaimList.size(); index++) {

						if(publicClaims.get(index).getType().equals(vcClaimList.get(index).getType())){
							Claim claim = new Claim();
							claim.setType(vcClaimList.get(index).getType());
							claim.setValue(vcClaimList.get(index).getValue());

							// 중복은 추가하지 않음
							if(!newVcClaimList.contains(claim))
								newVcClaimList.add(claim);

							newProof.add(proof.get(index));

						}
					}

					CredentialSubject newCredentialSubject = new CredentialSubject();
					newCredentialSubject.setPublicClaims(newVcClaimList);
					newCredentialSubject.setId(credentialSubject.getId());

					vc.setCredentialSubject(newCredentialSubject);
					vc.setProof(newProof);

					filteredByRequestInfo.add(vc);
				}
			}
		}

		 */

		// condition에 일치하는 vc 조회 테스트 시 생략
		/*
		List<VerifiableCredential> filteredByConditionList = new ArrayList<>();

		if (conditionList != null) {
			for (VerifiableCredential vc : vcList) {
				boolean shouldAdd = false;

				for (SubmissionCondition submissionCondition : conditionList) {
					List<String> schemaList = submissionCondition.getSchemaList();
					SubmissionFilter filter = submissionCondition.getFilter();
					if (schemaList.isEmpty() || schemaList.contains(vc.getSchema().getId())) {
						if (checkFilter(filter, vc)) {
							shouldAdd = true;
							break;
						}
					}
				}


				if (shouldAdd) {
					filteredByConditionList.add(vc);
				}
			}
		}

		Set<String> credentialSubject_id = new HashSet<>();
		for(int i=0; i<filteredByConditionList.size(); i++){
			credentialSubject_id.add(filteredByConditionList.get(i).getCredentialSubject().getId());
		}
		*/

		// proofValue 제거
		for(int i=0; i < vcList.size(); i++){
			List<Proof> proofList = vcList.get(i).getProof();
			List<Proof> newProofList = new ArrayList<>();
			for(int j=0; j<proofList.size(); j++){
				Proof proof = proofList.get(j);
				proof.setProofValue(null);
				newProofList.add(proof);
			}
			vcList.get(i).setProof(newProofList);
		}


		VerifiablePresentation verifiablePresentation = new VerifiablePresentation();
		verifiablePresentation.setHolder(vcList.get(0).getCredentialSubject().getId());
		//verifiablePresentation.setContext();
		//verifiablePresentation.setType();
		//verifiablePresentation.setId();

		// context list 우선 1개
		List<String> context = new ArrayList<String>();
		String contextStr = "https://www.w3.org/2018/credentials/v1";
		context.add(contextStr);
		verifiablePresentation.setContext(context);
		// type list 우선 1개
		List<String> type = new ArrayList<String>();
		String typeStr = "VerifiablePresentation";
		type.add(typeStr);
		verifiablePresentation.setType(type);
		// id 하드코딩
		verifiablePresentation.setId("a794abc1-a715-4c96-91e0-959440df7ced");
		verifiablePresentation.setExpirationDate(expirationDate);
		verifiablePresentation.setVerifiableCredential((ArrayList<VerifiableCredential>) vcList);

		return verifiablePresentation;
	}

	public VcResult verify(VcVerifyParam verifyParam, VerifiablePresentation verifiablePresentation) throws DIDManagerException {

		VcResult vcResult = new VcResult();
		// 1. vp 만료기한 체크
		String vpExpirationDate = verifiablePresentation.getExpirationDate();

		boolean isExpirationDate = isExpirationDate(vpExpirationDate);
		if (isExpirationDate) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_EXPIRED_VP);
		}
		;

		// 2. delegate 체크
		boolean isDelegate = isDelegate(verifiablePresentation.getHolder(),
				verifiablePresentation.getVerifiableCredential());
		if (isDelegate) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_DELEGATED_VP);
		}
		;

		// 3. condition 검증
		checkServiceCode(verifyParam.getConditionList(), verifiablePresentation.getVerifiableCredential());

		// 4.- vp 서명 원문 추출 // pinKey_exception
		List<SignatureParams> vpSigParams = getVpDataToVerify(verifiablePresentation, verifyParam.getHolderDIDDocument());

		// 5. vc 만료기한 체크 - public claims 서명 원문 추출
		List<SignatureParams> pubClaimsSigParamsToVerify = getPublicClaimsDatatToVerify(
				verifiablePresentation.getVerifiableCredential(), verifyParam.getIssuerDIDDocument(),
				verifyParam.isCheckVcExpirationDate());

		// 6. private claims 서명 원문 추출
		List<SignatureParams> priClaimsSigParamsToVerify = getPriClaimsDataToVerify(
				verifiablePresentation.getVerifiableCredential(), verifyParam.getIssuerDIDDocument());

		vcResult.setStatus("1");
		vcResult.setVerifiablePresentation(verifiablePresentation);
		vcResult.setVpSigParamsToVerify(vpSigParams);
		vcResult.setClaimsSigParamsToVerify(pubClaimsSigParamsToVerify);
		vcResult.setExtClaimsSigParamsToVerify(priClaimsSigParamsToVerify);
		return vcResult;

	}

	private List<SignatureParams> getPriClaimsDataToVerify(List<VerifiableCredential> verifiableCredentials,
			DIDDocument userDidDocument) throws DIDManagerException {
		List<SignatureParams> privateSignatureparams = new ArrayList<SignatureParams>();

		for (VerifiableCredential verifiableCredential : verifiableCredentials) {
			VerifiableCredential tmpVerifiableCredential = new VerifiableCredential();
			tmpVerifiableCredential.fromJson(verifiableCredential.toJson());

			CredentialSubject credentialSubject = tmpVerifiableCredential.getCredentialSubject();
			if (credentialSubject.getExtension() == null) {
				return null;
			}

			if (tmpVerifiableCredential.getCredentialSubject().getClaims() != null) {
				tmpVerifiableCredential.getCredentialSubject().setClaims(null);
			}

			for (Proof proof : credentialSubject.getExtension().getProof()) {

				Proof tmpProof = new Proof();
				tmpProof.setCreated(proof.getCreated());
				tmpProof.setProofPurpose(proof.getProofPurpose());
				tmpProof.setVerificationMethod(proof.getVerificationMethod());

				List<Proof> tmpProofs = new ArrayList<Proof>();
				tmpProofs.add(tmpProof);
				tmpVerifiableCredential.getCredentialSubject().getExtension().setProof(tmpProofs);
				tmpVerifiableCredential.setProof(null);

				SignatureParams signatureParam = new SignatureParams();
				signatureParam.setData(tmpVerifiableCredential.toJson());
				signatureParam.setSignatureValue(proof.getProofValue());

				// pinKey_exception
//				PublicKey publicKey = userDidDocument.getPublicKey(proof.getVerificationMethod());
//				if (publicKey == null) {
//					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_EXIST_SIGNING_KEY);
//				}
//				signatureParam.setPublicKey(publicKey.getPublicKeyMultibase());
//				String algString = publicKey.getType().contains("Secp256r1") ? "Secp256r1" : "Secp256k1";
//				signatureParam.setAlgString(algString);

				privateSignatureparams.add(signatureParam);
			}

		}

		return privateSignatureparams;
	}

	private List<SignatureParams> getPublicClaimsDatatToVerify(List<VerifiableCredential> verifiableCredentials,
			DIDDocument issuerDidDocument, boolean isCheckVcExpirationDate) throws DIDManagerException {
		List<SignatureParams> publicSignatureparams = new ArrayList<SignatureParams>();

		// 현재 로직에서 verifiableCredentials size 1
		for (VerifiableCredential verifiableCredential : verifiableCredentials) {

			// vc 만료시간 체크
			if (isCheckVcExpirationDate) {
				boolean isExpirationDate = isExpirationDate(verifiableCredential.getExpirationDate());

				if (isExpirationDate) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_EXPIRED_VC, verifiableCredential.getId());
				}
			}

			if (verifiableCredential.getCredentialSubject() != null) {
				List<Claims> claims = verifiableCredential.getCredentialSubject().getClaims();

				if (claims == null) {
					return null;
				}

				// verifiableCredential - public claims 분리...
				for (int i = 0; i < claims.size(); i++) {
					VerifiableCredential tmpVerifiableCredential = new VerifiableCredential();
					tmpVerifiableCredential.fromJson(verifiableCredential.toJson());

					Extension extension = tmpVerifiableCredential.getCredentialSubject().getExtension();
					if (extension != null) {
						tmpVerifiableCredential.getCredentialSubject().setExtension(null);
					}

					// public claim 재설정
					List<Claims> tmpClaims = new ArrayList<Claims>();
					tmpClaims.add(claims.get(i));

					tmpVerifiableCredential.getCredentialSubject().setClaims(tmpClaims);

					// proof 재설정
					Proof proofInVc = tmpVerifiableCredential.getProof().get(0);
					Proof tmpProof = new Proof();
					tmpProof.setCreated(proofInVc.getCreated());
					tmpProof.setProofPurpose(proofInVc.getProofPurpose());
					tmpProof.setVerificationMethod(proofInVc.getVerificationMethod());

					List<Proof> tmpProofs = new ArrayList<Proof>();
					tmpProofs.add(tmpProof);
					tmpVerifiableCredential.setProof(tmpProofs);

					// signatureParam 설정
					SignatureParams signatureParam = new SignatureParams();
					signatureParam.setData(tmpVerifiableCredential.toJson());
					signatureParam.setSignatureValue(proofInVc.getProofValueList().get(i));

					// pinKey_exception
//					PublicKey publicKey = issuerDidDocument.getPublicKey(tmpProof.getVerificationMethod());
//					if (publicKey == null) {
//						throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_EXIST_SIGNING_KEY);
//					}
//					signatureParam.setPublicKey(publicKey.getPublicKeyMultibase());
//					String algString = publicKey.getType().contains("Secp256r1") ? "Secp256r1" : "Secp256k1";
//					signatureParam.setAlgString(algString);

					publicSignatureparams.add(signatureParam);
				}

			}
		}

		return publicSignatureparams;
	}

	private List<SignatureParams> getVpDataToVerify(VerifiablePresentation verifiablePresentation, DIDDocument userDidDocument) throws DIDManagerException {

		VerifiablePresentation tmpVerifiablePresentation = new VerifiablePresentation();
		tmpVerifiablePresentation.fromJson(verifiablePresentation.toJson());

		List<SignatureParams> signatureParams = new ArrayList<SignatureParams>();
		// 현재 proof 는 size 1
		for (Proof proof : tmpVerifiablePresentation.getProof()) {
			Proof tmpProof = new Proof();
			tmpProof.setCreated(proof.getCreated());
			tmpProof.setProofPurpose(proof.getProofPurpose());
			tmpProof.setVerificationMethod(proof.getVerificationMethod());

			List<Proof> proofs = new ArrayList<Proof>();
			proofs.add(tmpProof);
			tmpVerifiablePresentation.setProof(proofs);

			SignatureParams signatureParam = new SignatureParams();
			signatureParam.setData(tmpVerifiablePresentation.toJson());
			signatureParam.setSignatureValue(proof.getProofValue());
			PublicKey publicKey = userDidDocument.getPublicKey(tmpProof.getVerificationMethod());

			// pinKey_exception
			if (publicKey == null) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_EXIST_SIGNING_KEY);
			}
			signatureParam.setPublicKey(publicKey.getPublicKeyMultibase());
			String algString = publicKey.getType().contains("Secp256r1") ? "Secp256r1" : "Secp256k1";
			signatureParam.setAlgString(algString);

			signatureParams.add(signatureParam);
		}
		return signatureParams;

	}

	private void checkServiceCode(List<Condition> conditionList, List<VerifiableCredential> VerifiableCredentials)
			throws DIDManagerException {

		if (conditionList == null || conditionList.isEmpty()) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_EMPTY_CONDITIONLIST);
		}

		for (Condition condition : conditionList) {
			checkSchemaList(condition.getSchemaList(), VerifiableCredentials);
			checkFilter(condition.getFilter(), VerifiableCredentials);
		}

	}

	private void checkFilter(Filter filter, List<VerifiableCredential> verifiableCredentials) throws DIDManagerException {

		if(filter == null) {
			return;// 에러 처리???/
		}
		Set<String> tmpAlList = new HashSet<String>();
		Set<String> tmpIssuerList = new HashSet<String>();
		Set<String> tmpClaimList = new HashSet<String>();

		for (VerifiableCredential verifiableCredential : verifiableCredentials) {

			tmpAlList.add(verifiableCredential.getEvidenceLevel());
			tmpIssuerList.add(verifiableCredential.getIssuer().getId());

			List<Claims> claims = verifiableCredential.getCredentialSubject().getClaims();
			if (claims == null || claims.size() == 0) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_PRIVACY_NOT_EXIST);
			}
			for (Claims claim : claims) {
				tmpClaimList.add(claim.getCode());
			}

		}


		checkAlList(filter.getAlList(), tmpAlList);

		checkIssuerList(filter.getIssuerList(), tmpIssuerList);

		checkRequiredClaimList(filter.getRequiredClaimList(), tmpClaimList);

	}

	private void checkRequiredClaimList(List<String> requiredClaimList, Set<String> tmpClaimList) throws DIDManagerException {
		if (requiredClaimList != null && !requiredClaimList.isEmpty()) {

			for (String reqClaim : requiredClaimList) {
				boolean isValidClaim = tmpClaimList.contains(reqClaim);
				if (!isValidClaim) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_NOT_CONTAIN_CLAIM);
				}
			}
		}

	}

	private void checkIssuerList(List<String> issuerList, Set<String> tmpIssuerList) throws DIDManagerException {
		if (issuerList != null && !issuerList.isEmpty()) {
			for (String issuer : tmpIssuerList) {
				boolean isValidIssuer = issuerList.contains(issuer);
				if (!isValidIssuer) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_NOT_ALLOW_ISSUER);
				}
			}
		}

	}

	private void checkAlList(List<String> alList, Set<String> tmpAlList) throws DIDManagerException {
		if (alList != null && !alList.isEmpty()) {
			for (String al : tmpAlList) {
				boolean isValidAlList = alList.contains(al);
				if (!isValidAlList) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_NOT_ALLOW_AL);
				}
			}
		}
	}

	private void checkSchemaList(List<String> schemaList, List<VerifiableCredential> verifiableCredentials)
			throws DIDManagerException {

		if (schemaList != null && !schemaList.isEmpty()) {
			for (VerifiableCredential verifiableCredential : verifiableCredentials) {
				boolean isValidSchema = schemaList.contains(verifiableCredential.getSchema().getId());
				if (!isValidSchema) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_VPMANAGER_NOT_ALLOW_SCHEMA);
				}
			}
		}

	}

	private boolean isDelegate(String vpDid, List<VerifiableCredential> verifiableCredentials) {

		boolean isDelegate = false;
		for(VerifiableCredential verifiableCredential : verifiableCredentials) {
			String vcOwnerDid = verifiableCredential.getCredentialSubject().getId();

			if(!vpDid.equals(vcOwnerDid)) {
				isDelegate = true;
				break;

			}
		}
	    return isDelegate;
	}


	private boolean isExpirationDate(String expirationDate) {
		ZonedDateTime expirationZonedDateTime = VerifiableCredential.stringToDate(expirationDate);
		ZonedDateTime nowZonedDateTime = ZonedDateTime.now(ZoneId.of("UTC+0"));
		if (expirationZonedDateTime.isBefore(nowZonedDateTime)) {
			// 만료
			return true;
		}
		//return expirationZonedDateTime.isBefore(nowZonedDateTime);
		return false;
	}

}
