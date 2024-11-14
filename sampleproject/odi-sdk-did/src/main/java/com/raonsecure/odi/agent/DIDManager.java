package com.raonsecure.odi.agent;

import java.io.IOException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.did.PublicKey;
import com.raonsecure.odi.agent.data.did.Service;
import com.raonsecure.odi.agent.data.rest.KeyInfo;
import com.raonsecure.odi.agent.data.rest.ServiceInfo;
import com.raonsecure.odi.agent.data.rest.SignatureParams;
import com.raonsecure.odi.agent.util.IWDIDFile;
import com.raonsecure.odi.agent.enums.did.DIDKeyType;
import com.raonsecure.odi.agent.enums.did.DIDMethodType;
import com.raonsecure.odi.agent.enums.did.DIDStatus;
import com.raonsecure.odi.agent.enums.did.KeyPurpose;
import com.raonsecure.odi.agent.enums.did.ServiceId;
import com.raonsecure.odi.agent.enums.did.ServiceType;
import com.raonsecure.odi.agent.exception.DIDManagerErrorCode;
import com.raonsecure.odi.agent.exception.DIDManagerException;

public class DIDManager {

	public DIDDocument didDocument;

	public DIDDocument tmpDIDDocument;

	private IWDIDFile iwD;

	public DIDManager() {

	}

	public DIDManager(String pathWithName) {
		iwD = new IWDIDFile(pathWithName);
	}

	public boolean isExistDID() {
		return iwD.isExist();
	}



//	public DIDManager(String didJson) {
//		didDocument = new DIDDocument(didJson);
//	}

	public DIDDocument getDIDDocument() {
		return this.didDocument;
	}

	// account 데이터 확인 필요 , 정규식규칙 mdl과 동일한지 확인 필요
	public String genDID(String methodName, String account) throws DIDManagerException {

		if (!methodName.matches("^[0-9a-z:]+$"))
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_INVALID_METHODNAME);

		if (methodName == null || methodName.length() < 1 || methodName.length() > 20) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_INVALID_METHODNAME);
		}

		return "did:" + methodName + ":" + account;
	}

	public void makeDIDDocument(String da, List<KeyInfo> keyInfos, ServiceInfo serviceInfo) throws DIDManagerException {
		if (keyInfos == null || keyInfos.size() == 0) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_ADD_KEY_FAIL);
		}
		if (da == null || da.isEmpty()) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_DA_IS_NULL);
		}
		// init()
		didDocument = new DIDDocument();
		didDocument.setContext("https://www.w3.org/ns/did/v1");
		didDocument.setId(da);
		didDocument.setController(da);

		// addKey(and link set)
		for (KeyInfo keyInfo : keyInfos) {

			boolean checkNotNull = Stream.of(keyInfo.getAlgoType(), keyInfo.getKeyId(), keyInfo.getMethodType(), keyInfo.getPublicKey(), keyInfo.getController()).allMatch(Objects::nonNull);
			if(!checkNotNull) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_INSUFFICIENT_INFOS);
			}

			try {
				DIDMethodType.fromRawValue(keyInfo.getMethodType());
			} catch (IllegalArgumentException e) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
			}

			addKey(keyInfo);
		}

		// service set
		if (serviceInfo != null) {
			addService(serviceInfo);

		}

		didDocument.setUpdated(DIDDocument.dateToString(ZonedDateTime.now(ZoneId.of("UTC"))));

	}

	public void addService(ServiceInfo serviceInfo) throws DIDManagerException {

		List<Service> services = didDocument.getService();
		if (didDocument.getService() == null && (serviceInfo != null)) {
			services = new ArrayList<Service>();
		}

		for (Service service : services) {
			if (serviceInfo.getServiceType().getRawValue().equals(service.getType())) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_EXIST_SERVICE_TYPE);
			}
		}

		Service service = makeServiceFromServiceInfo(didDocument.getId(), serviceInfo);
		services.add(service);

		didDocument.setService(services);

	}

	// 서명을 위한 params
	public List<SignatureParams> getSignatureParams(List<String> keyIds) throws DIDManagerException {
		// didDocument 원문 생성.. 에 필요
		List<SignatureParams> SignatureParams = new ArrayList<SignatureParams>();
		List<String> signableKeyIds = this.getSignableKeyIds();

		if (keyIds != null && !keyIds.isEmpty()) {
			ZonedDateTime createdDate = ZonedDateTime.now(ZoneId.of("UTC"));
			for (String keyId : keyIds) {

				PublicKey publicKey = getPublicKey(keyId);
				if (publicKey == null) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_UNREGISTERED_KEY);
				}

				// 서명키인지 확인
				if (!signableKeyIds.contains(keyId)) {
					throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_A_SIGNING_KEY);
				}

				SignatureParams signatureParam = new SignatureParams();

				// 서명 원문 생성
				if (didDocument.getProof() != null) {
					didDocument.getProof().clear();
				}
				Proof proof = new Proof();
				proof.setCreated(DIDDocument.dateToString(createdDate));
				// purpose는 키의 링크 설정
				proof.setProofPurpose(getLinkedField( keyId).iterator().next().getName());
				proof.setVerificationMethod(getDidKeyId(this.didDocument.getId(), keyId));

				didDocument.setProof(proof);

				// keyId, 서명 원문,purpose 설정
				signatureParam.setKeyId(keyId);
				signatureParam.setKeyType(publicKey.getType());
				signatureParam.setData(this.didDocument.toJson());
				signatureParam.setKeyPurpose(proof.getProofPurpose());

				SignatureParams.add(signatureParam);
			}
		}

		return SignatureParams.isEmpty() ? null : SignatureParams;

	}

	public Proof generateManagementProof(String didKeyId, KeyPurpose keyPurpose) {
//		public Proof generateManagementProof(String json, String didKeyId, KeyPurpose keyPurpose) {
//			Gson gson = new Gson();
//		    JsonElement jsonObject = gson.fromJson(json, JsonElement.class);
//
//			Proof proof = new Proof();
//			proof.setCreated(DIDDocument.dateToString(new Date()));
//			proof.setProofPurpose(keyPurpose.getRawValue());
//			proof.setVerificationMethod(didKeyId);
	//
//			JsonObject jsonObjectWithProof = jsonObject.getAsJsonObject();
//	        jsonObjectWithProof.add("proof", gson.toJsonTree(proof));
	//
//	        String addProofJson = gson.toJson(jsonObjectWithProof);
	//
//	        return addProofJson;

			Proof proof = new Proof();
			proof.setCreated(DIDDocument.dateToString(ZonedDateTime.now(ZoneId.of("UTC"))));
			proof.setProofPurpose(keyPurpose.getRawValue());
			proof.setVerificationMethod(didKeyId);

			return proof;

		}

	// 서명 검증을 위한  params
	public List<SignatureParams> getVerifySignatureParams() throws DIDManagerException {
	    List<SignatureParams> signatureParams = new ArrayList<SignatureParams>();
	    DIDDocument tmpDidDocument = new DIDDocument(this.didDocument.toJson());
	    List<Proof> tmpProofs = new ArrayList<>(tmpDidDocument.getProof());

	    for (Proof proof : tmpProofs) {
	    	tmpDidDocument.getProof().clear();
	        Proof tmpProof = new Proof();
	        tmpProof.setCreated(proof.getCreated());
	        tmpProof.setProofPurpose(proof.getProofPurpose());
	        tmpProof.setVerificationMethod(proof.getVerificationMethod());

	        tmpDidDocument.setProof(tmpProof);
	        SignatureParams signatureParam = new SignatureParams();
	        signatureParam.setData(tmpDidDocument.toJson());
	   //     signatureParam.setKeyId(getKeyId(tmpProof.getVerificationMethod()));
	        PublicKey publicKey = didDocument.getPublicKey(tmpProof.getVerificationMethod());
	        if(publicKey == null) {
	        	throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_EXIST_SIGNING_KEY);
	        }
	        signatureParam.setPublicKey(publicKey.getPublicKeyMultibase());
	        signatureParam.setAlgString(publicKey.getType().contains("Secp256r1") ? "Secp256r1" : "Secp256k1");
	        signatureParam.setSignatureValue(proof.getProofValue());

	        signatureParams.add(signatureParam);

	    }

	    return signatureParams;
	}



	public void addProof(List<SignatureParams> signatureParams) throws DIDManagerException {

		List<Proof> proofs = new ArrayList<Proof>();
		for (SignatureParams signatureParam : signatureParams) {
			DIDDocument didDocument = new DIDDocument(signatureParam.getData());
			Proof tmpProof = didDocument.getProof().get(0);

//			if (tmpProofs.size() != 1) {
//				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_INVALID_PROOF_SIZE);
//			}

			String keyIdByProof = this.getKeyId(tmpProof.getVerificationMethod());

			if (!keyIdByProof.equals(signatureParam.getKeyId())) {
				// 에러 코드 변경 필요
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_UNREGISTERED_KEY);
			}

			Proof proof = makeProof(signatureParam, tmpProof);
			proofs.add(proof);

		}

		 this.didDocument.setProof(proofs);
	}


	public void changeStatus(String keyId, DIDStatus status) throws DIDManagerException {
	    String didKeyId = getDidKeyId(this.didDocument.getId(), keyId);

	    boolean isVerificationMethod = false;
	    List<PublicKey> verificationMethods = this.didDocument.getVerificationMethod();

	    for (PublicKey publicKey : verificationMethods) {
	        if (publicKey.getId().equals(didKeyId)) {
	            publicKey.setStatus(status.getRawValue());
	            isVerificationMethod = true;
	            break;
	        }
	    }

	    if (!isVerificationMethod) {
	        throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_UNREGISTERED_KEY);
	    }

	    this.didDocument.setVerificationMethod(verificationMethods);
	}



	public DIDStatus getStatus( String keyId) throws DIDManagerException {
		PublicKey publicKey = getPublicKey(keyId);
		return DIDStatus.fromString(publicKey.getStatus());

	}

	private Proof makeProof(SignatureParams signatureParam, Proof proof) {
		Proof tmpProof = proof;
	//	proof.setType(signatureParam.getKeyType());
		proof.setType(signatureParam.getAlgString() + DIDKeyType.VERIFICATIONKEY.getRawValue());
		//proof.setCreated(proof.getCreated()));
		// didKeyId
		//proof.setVerificationMethod(proof.getVerificationMethod());
		//tmpProof.setProofPurpose(dataProof.getKeyPurpose().getRawValue());
		tmpProof.setProofValue(signatureParam.getSignatureValue());

		return tmpProof;
	}
	public void addKey(KeyInfo keyInfo) throws DIDManagerException {

		tmpDIDDocument = new DIDDocument(didDocument.toJson());

		if (keyInfo == null) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_ADD_KEY_FAIL);
		}

		boolean checkNotNull = Stream.of(keyInfo.getAlgoType(), keyInfo.getKeyId(), keyInfo.getMethodType(), keyInfo.getPublicKey(), keyInfo.getController()).allMatch(Objects::nonNull);
		if(!checkNotNull) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_INSUFFICIENT_INFOS);
		}

		try {
			DIDMethodType.fromRawValue(keyInfo.getMethodType());
		} catch (IllegalArgumentException e) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
		}

		if ((keyInfo.getMethodType() & DIDMethodType.KEY_AGREEMENT.getRawValue()) != 0
				&& (keyInfo.getMethodType() & (DIDMethodType.ASSERTION_METHOD.getRawValue()
						| DIDMethodType.AUTHENTICATION.getRawValue() | DIDMethodType.CAPABILITY_INVOCATION.getRawValue()
						| DIDMethodType.CAPABILITY_DELEGATION.getRawValue())) != 0) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
		}

		if(tmpDIDDocument.getVerificationMethod() != null && isVerificationMethods(tmpDIDDocument.getVerificationMethod(), keyInfo.getController()+"#"+keyInfo.getKeyId())) {
			tmpDIDDocument = null;
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_DUPLICATED_KEY);
		}

		PublicKey publicKey = new PublicKey();
		publicKey.setController(keyInfo.getController());
		publicKey.setId(getDidKeyId(this.didDocument.getId(), keyInfo.getKeyId()));
		publicKey.setPublicKeyMultibase(keyInfo.getPublicKey());

		if ((keyInfo.getMethodType() & DIDMethodType.KEY_AGREEMENT.getRawValue()) != 0) {
			publicKey.setType(keyInfo.getAlgoType() + DIDKeyType.KEYAGREEMENTKEY.getRawValue());
		} else {
			publicKey.setType(keyInfo.getAlgoType() + DIDKeyType.VERIFICATIONKEY.getRawValue());
		}

		publicKey.setStatus(DIDStatus.VALID.getRawValue());


		tmpDIDDocument.setVerificationMethod(publicKey);

		addLink(getDidKeyId(tmpDIDDocument.getId(), keyInfo.getKeyId()), keyInfo.getMethodType());
	}

	public void addLink( String didKeyId, int didMethodType) throws DIDManagerException {

		if (tmpDIDDocument == null) {
	        tmpDIDDocument = new DIDDocument(this.didDocument.toJson());
		}
		List<PublicKey> verificationMethods = tmpDIDDocument.getVerificationMethod();

		PublicKey publicKey = findPublicKey(verificationMethods, didKeyId);

		if ((didMethodType & DIDMethodType.ASSERTION_METHOD.getRawValue()) != 0) {
			if (!isVerificationKeyType(publicKey.getType())) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
			}
			checkInlinkedList(tmpDIDDocument.getAssertionMethod(), didKeyId);
			tmpDIDDocument.setAssertionMethod(didKeyId);
		}
		if ((didMethodType & DIDMethodType.AUTHENTICATION.getRawValue()) != 0) {
			if (!isVerificationKeyType(publicKey.getType())) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
			}
			checkInlinkedList(tmpDIDDocument.getAuthentication(), didKeyId);
			tmpDIDDocument.setAuthentication(didKeyId);
		}
		if ((didMethodType & DIDMethodType.KEY_AGREEMENT.getRawValue()) != 0) {
			if (isVerificationKeyType(publicKey.getType())) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
			}
			checkInlinkedList(tmpDIDDocument.getKeyAgreement(), didKeyId);
			tmpDIDDocument.setKeyAgreement(didKeyId);
		}
		if ((didMethodType & DIDMethodType.CAPABILITY_INVOCATION.getRawValue()) != 0) {
			if (!isVerificationKeyType(publicKey.getType())) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
			}
			checkInlinkedList(tmpDIDDocument.getCapabilityInvocation(), didKeyId);
			tmpDIDDocument.setCapabilityInvocation(didKeyId);
		}
		if ((didMethodType & DIDMethodType.CAPABILITY_DELEGATION.getRawValue()) != 0) {
			if (!isVerificationKeyType(publicKey.getType())) {
				throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
			}
			checkInlinkedList(tmpDIDDocument.getCapabilityDelegation(), didKeyId);
			tmpDIDDocument.setCapabilityDelegation(didKeyId);
		}
		this.didDocument = tmpDIDDocument;

	}

	private boolean isVerificationKeyType(String type) {
		boolean isVerificationKeyType = false;

		if (type.contains(DIDKeyType.VERIFICATIONKEY.getRawValue())) {
			isVerificationKeyType = true;
		}

		return isVerificationKeyType;
	}

	public void removeKey(String keyId) throws DIDManagerException {

		tmpDIDDocument = new DIDDocument(this.didDocument.toJson());

		List<PublicKey> verificationMethod = tmpDIDDocument.getVerificationMethod();
		String publicKeyId = getDidKeyId(didDocument.getId(), keyId);

		List<PublicKey> newVerificationMethod = removeVerificationMethod(verificationMethod, publicKeyId);
		tmpDIDDocument.setVerificationMethod(newVerificationMethod);

		EnumSet<DIDMethodType> methodTypeEnumSet = getLinkedField(keyId);

		for (DIDMethodType method : methodTypeEnumSet) {
			removeLink(keyId, method);
		}

		this.didDocument = tmpDIDDocument;
	}

	public EnumSet<DIDMethodType> getLinkedField(String keyId) throws DIDManagerException {
		EnumSet<DIDMethodType> methodTypeEnumSet = EnumSet.noneOf(DIDMethodType.class);

		if(tmpDIDDocument == null) tmpDIDDocument = new DIDDocument(this.didDocument.toJson());

		String publicKeyId = getDidKeyId(tmpDIDDocument.getId(), keyId);
		if (tmpDIDDocument.getAssertionMethod() != null && tmpDIDDocument.getAssertionMethod().contains(publicKeyId)) {
			methodTypeEnumSet.add(DIDMethodType.ASSERTION_METHOD);
		}

		if (tmpDIDDocument.getAuthentication() != null && tmpDIDDocument.getAuthentication().contains(publicKeyId)) {
			methodTypeEnumSet.add(DIDMethodType.AUTHENTICATION);
		}

		if (didDocument.getKeyAgreement() != null && tmpDIDDocument.getKeyAgreement().contains(publicKeyId)) {
			methodTypeEnumSet.add(DIDMethodType.KEY_AGREEMENT);
		}

		if (tmpDIDDocument.getCapabilityInvocation() != null && tmpDIDDocument.getCapabilityInvocation().contains(publicKeyId)) {
			methodTypeEnumSet.add(DIDMethodType.CAPABILITY_INVOCATION);
		}

		if (tmpDIDDocument.getCapabilityDelegation() != null && tmpDIDDocument.getCapabilityDelegation().contains(publicKeyId)) {
			methodTypeEnumSet.add(DIDMethodType.CAPABILITY_DELEGATION);
		}

		if (methodTypeEnumSet.isEmpty()) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_LINKED_KEY);
		}

		return methodTypeEnumSet;
	}

	public void removeLink(String keyId, DIDMethodType didMethodType) throws DIDManagerException {
	    if (tmpDIDDocument == null) {
	        tmpDIDDocument = new DIDDocument(didDocument.toJson());
	    }

	    String publicKeyId = getDidKeyId(didDocument.getId(), keyId);

	    switch (didMethodType) {
	        case ASSERTION_METHOD:
	            tmpDIDDocument.setAssertionMethod(removeDataFromList(didDocument.getAssertionMethod(), publicKeyId));
	            break;
	        case AUTHENTICATION:
	            tmpDIDDocument.setAuthentication(removeDataFromList(didDocument.getAuthentication(), publicKeyId));
	            break;
	        case KEY_AGREEMENT:
	            tmpDIDDocument.setKeyAgreement(removeDataFromList(didDocument.getKeyAgreement(), publicKeyId));
	            break;
	        case CAPABILITY_INVOCATION:
	            tmpDIDDocument.setCapabilityInvocation(removeDataFromList(didDocument.getCapabilityInvocation(), publicKeyId));
	            break;
	        case CAPABILITY_DELEGATION:
	            tmpDIDDocument.setCapabilityDelegation(removeDataFromList(didDocument.getCapabilityDelegation(), publicKeyId));
	            break;
	        default:
	            throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
	    }

	    this.didDocument = tmpDIDDocument;
	}



	public boolean checkMethodType(String keyId, DIDMethodType didMethodType) {
	    String didKeyId = getDidKeyId(didDocument.getId(), keyId);

	    return didDocument.checkMethodType(didKeyId, didMethodType);

	}

	public List<String> getSignableKeyIds() throws DIDManagerException {
	    List<String> keyIds = new ArrayList<>();

	    if (didDocument.getVerificationMethod() == null) {
	        throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_UNREGISTERED_KEY);
	    }

	    for (PublicKey publicKey : didDocument.getVerificationMethod()) {
	        if (publicKey.getType().contains(DIDKeyType.VERIFICATIONKEY.getRawValue())) {
	            keyIds.add(getKeyId(publicKey.getId()));
	        }
	    }

	    return keyIds.isEmpty() ? null : keyIds;
	}

	public List<String> getLinkValues(DIDMethodType didMethodType) throws DIDManagerException {
	    List<String> didKeyIds = null;

	    switch (didMethodType) {
	        case ASSERTION_METHOD:
	            didKeyIds = didDocument.getAssertionMethod();
	            break;
	        case AUTHENTICATION:
	            didKeyIds = didDocument.getAuthentication();
	            break;
	        case KEY_AGREEMENT:
	            didKeyIds = didDocument.getKeyAgreement();
	            break;
	        case CAPABILITY_INVOCATION:
	            didKeyIds = didDocument.getCapabilityInvocation();
	            break;
	        case CAPABILITY_DELEGATION:
	            didKeyIds = didDocument.getCapabilityDelegation();
	            break;
	        default:
	            throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_WRONG_METHOD);
	    }

	    return didKeyIds;
	}


	public PublicKey getPublicKey(String keyId) throws DIDManagerException {
	    String didKeyId = getDidKeyId(didDocument.getId(), keyId);
	    return findPublicKey(didDocument.getVerificationMethod(), didKeyId);
	}


	private Service makeServiceFromServiceInfo(String id, ServiceInfo serviceInfo) {
	    Service service = new Service();

	    String serviceId = serviceInfo.getServiceType() == ServiceType.LINKED_DOMAINS
	            ? ServiceId.HOMEPAGE.getRawValue()
	            : ServiceId.CERTIFICATE.getRawValue();

	    service.setId(id + "#" + serviceId);
	    service.setServiceEndpoint(serviceInfo.getServiceUrl());
	    service.setType(serviceInfo.getServiceType().getRawValue());

	    return service;
	}


//	private List<String> removeDataFromList(List<String> linkedList, String didKeyId) throws DIDManagerException {
//
//		if (linkedList == null) {
//			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_EMPTY_LINKED_LIST);
//		}
//		if (!linkedList.contains(didKeyId)) {
//			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_LINKED_KEY);
//		}
//		linkedList.removeIf(data -> data.equals(didKeyId));
//
//		if (linkedList.isEmpty()) {
//			linkedList = null;
//		}
//
//		return linkedList;
//
//	}

//	테스트 필요
	private List<String> removeDataFromList(List<String> linkedList, String didKeyId) throws DIDManagerException {
	    if (linkedList == null) {
	        throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_EMPTY_LINKED_LIST);
	    }

	    if (!linkedList.remove(didKeyId)) {
	        throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_NOT_LINKED_KEY);
	    }

	    return linkedList.isEmpty() ? null : linkedList;
	}



	private List<PublicKey> removeVerificationMethod(List<PublicKey> verificationMethods, String didKeyId)
			throws DIDManagerException {

		// verificationMethod 에 해당 키가 존재하는지 확인
		boolean isVerificationMethods = isVerificationMethods(verificationMethods, didKeyId);

		if (!isVerificationMethods) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_UNREGISTERED_KEY);
		}

		// 키 삭제
		Iterator<PublicKey> iterator = verificationMethods.iterator();
		while (iterator.hasNext()) {
			PublicKey publicKey = iterator.next();
			if (publicKey.getId().equals(didKeyId)) {
				iterator.remove();
			}
		}
		return verificationMethods;
	}

	private String getDidKeyId(String id, String keyId) {
		// "did#keyId"
		return id + "#" + keyId;
	}

	// getKeyIdFromDidKeyId 함수명 변경 고려 중
	private String getKeyId(String didKeyId) {
		// "did#keyId"
		String keyId = didKeyId.split("#")[1];
		return keyId;
	}

//	private boolean isVerificationMethods(List<PublicKey> verificationMethods, String didKeyId) {
//		boolean isVerificationMethods = false;
//		for (PublicKey tmpPublicKey : verificationMethods) {
//			if (tmpPublicKey.getId().equals(didKeyId)) {
//				isVerificationMethods = true;
//				break;
//			}
//		}
//
//		return isVerificationMethods;
//	}
// test 필요
	private boolean isVerificationMethods(List<PublicKey> verificationMethods, String didKeyId) {
	    for (PublicKey publicKey : verificationMethods) {
	        if (publicKey.getId().equals(didKeyId)) {
	            return true;
	        }
	    }
	    return false;
	}

	private PublicKey findPublicKey(List<PublicKey> verificationMethods, String didKeyId)
			throws DIDManagerException {
		// verificationMethod 에 해당 키가 존재하는지 확인
		boolean isVerificationMethods = isVerificationMethods(verificationMethods, didKeyId);

		if (!isVerificationMethods) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_UNREGISTERED_KEY);
		}

		for (PublicKey publicKey : verificationMethods) {
			if (publicKey.getId().equals(didKeyId)) {
				return publicKey;
			}
		}
		return null;
	}

	//checkDuplicatedKeyInLink  함수명 변경 고려 중
	private void checkInlinkedList(List<String> linkedList, String publicKeyId) throws DIDManagerException {
		if (linkedList != null && linkedList.contains(publicKeyId)) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_DUPLICATED_KEY);
		}

	}

	public void saveToFile(String didsJson) throws IOException {

		iwD.write(didsJson);
	}

	public String loadToFile() throws DIDManagerException {
		if(!isExistDID()) {
			throw new DIDManagerException(DIDManagerErrorCode.ERR_CODE_DIDMANAGER_FILE_NOT_EXIST);
		}

		// 기존 DID Doucment 읽기
		DIDDocument data = iwD.getData();
		if (data == null)
			return null;

		return data.toJson();
	}
}
