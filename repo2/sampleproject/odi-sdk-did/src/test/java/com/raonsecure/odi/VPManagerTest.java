package com.raonsecure.odi;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.raonsecure.odi.agent.DIDManager;
import com.raonsecure.odi.agent.VPManager;
import com.raonsecure.odi.agent.data.param.VcVerifyParam;
import com.raonsecure.odi.agent.data.rest.SignatureParams;
import com.raonsecure.odi.agent.data.rest.VcResult;
import com.raonsecure.odi.agent.data.vc.Condition;
import com.raonsecure.odi.agent.data.vc.result.VcClaimsResult;
import com.raonsecure.odi.agent.data.vp.VerifiablePresentation;
import com.raonsecure.odi.agent.exception.DIDManagerException;
import com.raonsecure.odi.crypto.exception.CryptoException;

public class VPManagerTest {
	public static DIDManager holderDidManager;
	public static DIDManager issuerDidManager;

	@DisplayName("verify data")
	@Test
	public void verifySignForIVC() throws DIDManagerException, CryptoException {

		String holderDidsJson = "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"authentication\":[\"did:omn:user#pinKey\"],\"controller\":\"did:omn:user\",\"id\":\"did:omn:user\",\"updated\":\"2024-01-18T04:36:37\",\"verificationMethod\":[{\"authType\":2,\"controller\":\"did:omn:user\",\"id\":\"did:omn:user#pinKey\",\"publicKeyMultibase\":\"zcRUfrUBsHZ3damjji2SDtqr6R1AxT8dyQaXhwZGpeETm\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"}]}";
		String issuerDidsJson = "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"assertionMethod\":[\"did:omn:issuer#assert1\"],\"authentication\":[\"did:omn:issuer#auth1\"],\"capabilityInvocation\":[\"did:omn:issuer#invoke\"],\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer\",\"keyAgreement\":[\"did:omn:issuer#keyagree\"],\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3nCdZ9nDtweoZtPTNKXH8Bq9u1xNPkSG1qXXzBvDkjF7AjnDgu7pzuRLpz5FUv5GpbjfBurMtVPjNU3z7qTvprtAj\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"},{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"authentication\",\"proofValue\":\"z3s6xu8kmuGzsFQZmLbqP9UE7m85haV6uuqNgzwSJQj3bzUJLGcbu2gtnp9Axo7L6vXwTTYF8dZjoWgWkhV95tmsL1\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#auth1\"},{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"capabilityInvocation\",\"proofValue\":\"z3pzGmskKgF62s4AuhtAUpDyZTtdq3LvayT9NymyGN4yhm5hdJKBmuAszo8NCVHvd5PuF1qZXzeMm8hXm56PHmtQeZ\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#invoke\"}],\"updated\":\"2024-01-18T02:37:23\",\"verificationMethod\":[{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#assert1\",\"publicKeyMultibase\":\"zfbAcKThctxrX5psVKUCqtuS97ySsAmQgcMNGNm3PxvEi\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#auth1\",\"publicKeyMultibase\":\"zg2AEkmaHhZMDdhLtxxz5uau62bGYbzeaiZAfkH9iM1rb\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#keyagree\",\"publicKeyMultibase\":\"z21ya7rgv9dwjGxBTpdVzdRzmYSFu8pGWp4Zgp2QG17gBB\",\"status\":\"valid\",\"type\":\"Secp256r1KeyAgreementKey2019\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#invoke\",\"publicKeyMultibase\":\"ztSgdMTyFoztdTdUsvhMyqxmjFdCZhGdSY1R4VcarFNXL\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"}]}";
		String vp = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"expirationDate\":\"2030-12-31T16:23:40\",\"holder\":\"did:omn:user\",\"id\":\"a794abc1-a715-4c96-91e0-959440df7ced\",\"proof\":[{\"created\":\"2024-01-18T04:36:38\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3qyrpfsF6yricVPvLEar687cZGn6vcHGKkKxx1dmv51wE7jqtHLqEKkvzt2LsSwbz55YEhbjM2KpCrAqvoFuvfGtH\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:user#pinKey\"}],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":{\"claims\":[{\"attribute\":{\"format\":\"plain\",\"hideValue\":true,\"location\":\"inline\",\"type\":\"text\"},\"caption\":\"이름\",\"code\":\"das.v1.name\",\"value\":\"함초롬\"},{\"attribute\":{\"format\":\"plain\",\"hideValue\":true,\"location\":\"remote\",\"type\":\"text\"},\"caption\":\"url\",\"code\":\"das.v1.url\",\"value\":\"uaHR0cDovLzE5Mi4xNjguMC44Ni9vZGk\"}],\"extension\":{\"claims\":[{\"caption\":\"닉네임\",\"code\":\"issuer.nickname\",\"value\":\"보니는천재\"}],\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3mxrx7j2qEicLot3c1zAvHBEpcHXiQgfiaYkCcbUxaAsy8vBG9Njx8uBeLw8dAbQ2f1wo9DWoJcRzersABpD69K8r\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"}]},\"id\":\"did:omn:user\"},\"encoding\":\"UTF-8\",\"evidence\":[{\"documentPresence\":\"Digital\",\"evidenceDocument\":\"k1\",\"subjectPresence\":\"Digital\",\"type\":[\"DocumentVerification\"],\"verifier\":\"did:omn:issuer\"}],\"evidenceLevel\":\"AL1\",\"expirationDate\":\"9999-12-31T23:59:59\",\"formatVersion\":\"1.0\",\"id\":\"f4cae750-422d-4d4f-990e-30d7debfb8d0\",\"issuanceDate\":\"2024-01-18T02:37:23\",\"issuer\":{\"id\":\"did:omn:issuer\",\"name\":\"issuer name\"},\"language\":\"ko\",\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValueList\":[\"z3ma7uD2Sh7ac2rKHXQieJ6UoYKrgK7MsPrf4b8aGsEHbVFX48GJFosTbK6J484UNSAFapjCvbV5cdzScjuWcgRrj7\",\"z3qvhPX13ZwiPVRdaEgpkm8vuUVmBSUuWh34hETnCV71kV6LggHtD4AtMZMNwPKsqtUBaoHdAZyBorYsriq8xu94rn\"],\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"}],\"schema\":{\"id\":\"default schema\",\"name\":\"test schema\",\"version\":\"1.0\"},\"type\":[\"VerifiableCredential\",\"IdentityCredential\"]}]}";

		holderDidManager = new DIDManager(holderDidsJson);
		issuerDidManager = new DIDManager(issuerDidsJson);

		VerifiablePresentation verifiablePresentation = new VerifiablePresentation();
		verifiablePresentation.fromJson(vp);

		Condition condition = new Condition();
		String strCondition = "{\"displayClaimList\":[\"das.v1.name\"],\"filter\":{\"requiredClaimList\":[\"das.v1.name\"]},\"schemaList\":[\"default schema\"]}";
		condition.fromJson(strCondition);

		List<Condition> conditionList = new ArrayList<Condition>();
		conditionList.add(condition);

		VcVerifyParam verifyParam = new VcVerifyParam(conditionList, holderDidManager.getDIDDocument(),
				issuerDidManager.getDIDDocument());
		VPManager vpManager = new VPManager();

		VcResult vpResult = vpManager.verify(verifyParam, verifiablePresentation);

		// 1. holder 서명 검증 요청 데이터 추출
		List<SignatureParams> vpSignatureParams = new ArrayList<SignatureParams>();
		vpSignatureParams = vpResult.getVpSigParamsToVerify();

		System.out.println("1. vpSignatureParams :::");
		System.out.println("publicKey	:" + vpSignatureParams.get(0).getPublicKey());
		System.out.println("algo		:" + vpSignatureParams.get(0).getAlgString());
		System.out.println("sign		:" + vpSignatureParams.get(0).getSignatureValue());
		System.out.println("data		:" + vpSignatureParams.get(0).getData());

		// 2. claims 서명 검증 요청 데이터 추출
		List<SignatureParams> reqSignatureParams = vpResult.getClaimsSigParamsToVerify();
		System.out.println("" );
		System.out.println("2. extSignatureParams :::");
		for (SignatureParams reqSignatureParam : reqSignatureParams) {
			System.out.println("publicKey	:" + reqSignatureParam.getPublicKey());
			System.out.println("algo		:" + reqSignatureParam.getAlgString());
			System.out.println("sign		:" + reqSignatureParam.getSignatureValue());
			System.out.println("data		:" + reqSignatureParam.getData());
			System.out.println("" );
		}
		List<SignatureParams> extSignatureParams = vpResult.getExtClaimsSigParamsToVerify();
		System.out.println("3. extSignatureParams :::");
		System.out.println("publicKey	:" + extSignatureParams.get(0).getPublicKey());
		System.out.println("algo		:" + extSignatureParams.get(0).getAlgString());
		System.out.println("sign		:" + extSignatureParams.get(0).getSignatureValue());
		System.out.println("data		:" + extSignatureParams.get(0).getData());

		// 3. privacy 추출
		VcClaimsResult vcClaimsResult = vpResult.getVcClaimsResult();
		System.out.println("" );
		System.out.println("4. privacy :::");
		System.out.println("vcClaimsResult	:" +  vcClaimsResult.toJson());

	}
}