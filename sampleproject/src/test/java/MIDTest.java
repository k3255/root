import com.raonsecure.odi.agent.DIDManager;
import com.raonsecure.odi.agent.VCManager;
import com.raonsecure.odi.agent.VPManager;
import com.raonsecure.odi.agent.data.did.DIDDocument;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.data.param.IssueVcParam;
import com.raonsecure.odi.agent.data.param.VcVerifyParam;
import com.raonsecure.odi.agent.data.rest.*;
import com.raonsecure.odi.agent.data.vc.*;
import com.raonsecure.odi.agent.data.vc.result.VcClaimsResult;
import com.raonsecure.odi.agent.data.vp.VerifiablePresentation;
import com.raonsecure.odi.agent.enums.did.DIDMethodType;
import com.raonsecure.odi.agent.enums.vc.EvidenceLevel;
import com.raonsecure.odi.agent.enums.vc.SubjectType;
import com.raonsecure.odi.crypto.digest.Sha256;
import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.util.MultiBase;
import com.raonsecure.odi.wallet.exception.IWException;
import com.raonsecure.odi.wallet.key.IWKeyManager;
import com.raonsecure.odi.wallet.key.IWKeyManagerInterface;
import com.raonsecure.odi.wallet.key.data.IWKey;
import com.raonsecure.odi.wallet.util.SignatureUtil;
import com.raonsecure.odi.wallet.util.json.GsonWrapper;
import com.raonsecure.oid.crypto.encoding.Base58;
import mock.IssuerConstants;
import mock.LadgerMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static mock.IssuerConstants.issuerDidDoc;

/**
 *
 * holder의 didDoc, wallet 기준이며, 블록체인에 저장되는 클래스는 BlockChain에 구현
 * issuer와 verifier의 didDoc 및 Key 정보는 메모리에 하드코딩
 * */

class MIDTest {

    private IWKeyManager keyManager;
    private DIDManager didManager;
    private VCManager vcManager;

    @BeforeEach
    void setUp() {
        String[] fileNames = {"./i.wallet", "./i.did"};
        for (String fileName : fileNames) {
            deleteFile(fileName);
        }
    }

    @AfterEach
    void tearDown() {

    }

    @DisplayName("MID Testcase")
    @Test
    void start() throws Exception {

        // 1.월렛 생성 및 unlock
        generateWalletAndUnlock();

        // 2. 키 생성
        generateKeyPair();

        // 서명 / 검증
        getSignVerifySignTest();

        // 3. DID doc 생성
        makeDID();

        Thread.sleep(1000);
        // 4. VC 발급
        VcResult vc = issueVC();

        // 5. VC 저장
        storeVC(vc);

        // 6. VP 제출
        VerifiablePresentation vp = submitVP();

        // 7. VP 검증
        verifyVP(vp);
    }

    void getSignVerifySignTest() throws Exception {
        System.out.println("signVerify");

        String source = "verify";
        SignatureUtil signatureUtil = new SignatureUtil();

        byte[] singedData = keyManager.getSign("assert", source.getBytes(StandardCharsets.UTF_8));

        signatureUtil.verifySign(keyManager.getPublicKey("assert"), source,
                MultiBase.encode(singedData, MultiBaseEnum.Base58btc), keyManager.getAlgoType("assert"));
    }

    private void verifyVP(VerifiablePresentation verifiablePresentation) throws Exception {
        System.out.println("verifyVP");

        DIDManager issuerDidManager = new DIDManager(issuerDidDoc);

        Condition condition = new Condition();
        String strCondition = "{\"displayClaimList\":[\"das.v1.name\"],\"filter\":{\"requiredClaimList\":[\"das.v1.name\"]},\"schemaList\":[\"default schema\"]}";
        condition.fromJson(strCondition);

        List<Condition> conditionList = new ArrayList<Condition>();
        conditionList.add(condition);

        VcVerifyParam verifyParam = new VcVerifyParam(conditionList, didManager.getDIDDocument(),
                issuerDidManager.getDIDDocument());
        VPManager vpManager = new VPManager();

        VcResult vpResult = vpManager.verify(verifyParam, verifiablePresentation);
        System.out.println("VPResult : " + vpResult.getStatus());
        // 1. holder 서명 검증 요청 데이터 추출
        List<SignatureParams> vpSignatureParams = new ArrayList<SignatureParams>();
        vpSignatureParams = vpResult.getVpSigParamsToVerify();

        System.out.println("1. vpSignatureParams :::");
        System.out.println("publicKey	:" + vpSignatureParams.get(0).getPublicKey());
        System.out.println("algo		:" + vpSignatureParams.get(0).getAlgString());
        System.out.println("sign		:" + vpSignatureParams.get(0).getSignatureValue());
        System.out.println("data		:" + vpSignatureParams.get(0).getData());

        // vp 검증
        // vpSignatureParams.get(0).getSignatureValue()) 와 vpSignatureParams.get(0).getData()를 sign하여 비교
        byte[] signature = keyManager.getSign("assert",vpSignatureParams.get(0).getData().getBytes());
        String signature1 = Base58.encode(signature);
        System.out.println("signature1 : " + signature1);

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

    private VerifiablePresentation submitVP() throws Exception {
        System.out.println("submitVP");
        /** 안드로이드 소스에서 VP 생성 로직 가져와야 함
         * i.wallet에 저장된 VC를 가져와서 VerifiablePresentation으로 변환 해야 함
         * pinKey 생성 로직 및 서명 확인 부분을 주석으로 처리 함 (소스 검색: pinKey_exception)
         */
        VPManager vpManager = new VPManager();

        // wallet에 저장된 VC 가져오기
        List<VerifiableCredential> vcList = keyManager.getCredentials();
        System.out.println("VCLIST : " + vcList.get(0).toString());

        //만료일
        String expirationDate = "2050-12-31T16:23:40";
        VerifiablePresentation verifiablePresentation = vpManager.makePresentation(vcList, expirationDate);

        //////////////////////////////////////////////////////////////////////////
        //vp 서명 해야함 holder의 pinkey
        Proof proof = new Proof();
        proof.setType("Secp256r1VerificationKey2018");
        proof.setProofPurpose("assertionMethod");

        System.out.println("verifiablePresentation without Sign: " + verifiablePresentation.toJson());
        byte[] signature = keyManager.getSign("assert",verifiablePresentation.toJson().getBytes());
        proof.setProofValue(Base58.encode(signature));
        proof.setVerificationMethod("did:omn:user#assert");
        proof.setCreated("2024-02-29T04:36:38");

        List<Proof> proofs = new ArrayList<>();
        proofs.add(proof);
        verifiablePresentation.setProof(proofs);
        System.out.println("verifiablePresentation with Sign: " + verifiablePresentation.toJson());
        //System.out.println("keyId pin : " + keyManager.getPublicKey("assert"));

        //////////////////////////////////////////////////////
        /*
        String vp = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"expirationDate\":\"2030-12-31T16:23:40\",\"holder\":\"did:omn:user\",\"id\":\"a794abc1-a715-4c96-91e0-959440df7ced\",\"proof\":[{\"created\":\"2024-01-18T04:36:38\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3qyrpfsF6yricVPvLEar687cZGn6vcHGKkKxx1dmv51wE7jqtHLqEKkvzt2LsSwbz55YEhbjM2KpCrAqvoFuvfGtH\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:user#pinKey\"}],\"type\":[\"VerifiablePresentation\"],\"verifiableCredential\":[{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"credentialSubject\":{\"claims\":[{\"attribute\":{\"format\":\"plain\",\"hideValue\":true,\"location\":\"inline\",\"type\":\"text\"},\"caption\":\"이름\",\"code\":\"das.v1.name\",\"value\":\"함초롬\"},{\"attribute\":{\"format\":\"plain\",\"hideValue\":true,\"location\":\"remote\",\"type\":\"text\"},\"caption\":\"url\",\"code\":\"das.v1.url\",\"value\":\"uaHR0cDovLzE5Mi4xNjguMC44Ni9vZGk\"}],\"extension\":{\"claims\":[{\"caption\":\"닉네임\",\"code\":\"issuer.nickname\",\"value\":\"보니는천재\"}],\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3mxrx7j2qEicLot3c1zAvHBEpcHXiQgfiaYkCcbUxaAsy8vBG9Njx8uBeLw8dAbQ2f1wo9DWoJcRzersABpD69K8r\",\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"}]},\"id\":\"did:omn:user\"},\"encoding\":\"UTF-8\",\"evidence\":[{\"documentPresence\":\"Digital\",\"evidenceDocument\":\"k1\",\"subjectPresence\":\"Digital\",\"type\":[\"DocumentVerification\"],\"verifier\":\"did:omn:issuer\"}],\"evidenceLevel\":\"AL1\",\"expirationDate\":\"9999-12-31T23:59:59\",\"formatVersion\":\"1.0\",\"id\":\"f4cae750-422d-4d4f-990e-30d7debfb8d0\",\"issuanceDate\":\"2024-01-18T02:37:23\",\"issuer\":{\"id\":\"did:omn:issuer\",\"name\":\"issuer name\"},\"language\":\"ko\",\"proof\":[{\"created\":\"2024-01-18T02:37:23\",\"proofPurpose\":\"assertionMethod\",\"proofValueList\":[\"z3ma7uD2Sh7ac2rKHXQieJ6UoYKrgK7MsPrf4b8aGsEHbVFX48GJFosTbK6J484UNSAFapjCvbV5cdzScjuWcgRrj7\",\"z3qvhPX13ZwiPVRdaEgpkm8vuUVmBSUuWh34hETnCV71kV6LggHtD4AtMZMNwPKsqtUBaoHdAZyBorYsriq8xu94rn\"],\"type\":\"Secp256r1VerificationKey2018\",\"verificationMethod\":\"did:omn:issuer#assert1\"}],\"schema\":{\"id\":\"default schema\",\"name\":\"test schema\",\"version\":\"1.0\"},\"type\":[\"VerifiableCredential\",\"IdentityCredential\"]}]}";
        System.out.println("vp : " + vp);
        VerifiablePresentation verifiablePresentation = new VerifiablePresentation();
        verifiablePresentation.fromJson(vp);

         */
        return verifiablePresentation;
    }

    void storeVC(VcResult vc) throws Exception {
        System.out.println("storeVC");
        keyManager.addCredential(vc.getVerifiableCredentialWithoutSign().toJson());

    }

    void generateKeyPair() throws Exception {
        System.out.println("generateKeyPair");
        keyManager.generateRandomKey("assert", IWKey.ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue());
        keyManager.generateRandomKey("auth", IWKey.ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue());
        keyManager.generateRandomKey("keyagree", IWKey.ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue());
        keyManager.generateRandomKey("invoke", IWKey.ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue());
        // pinkey 대신 assert를 쓰면 될듯
        //keyManager.generateRandomKey("pin", IWKey.ALGORITHM_TYPE.ALGORITHM_SECP256r1.getValue());
    }

    void makeDID() throws Exception {
        System.out.println("makeDID");
        didManager = new DIDManager("./i.did");
        String did = didManager.genDID("omn", "user");

        List<KeyInfo> keyInfos = new ArrayList<>();

        // assertionMethod 키 정보
        keyInfos.add(createKeyInfo("assert",
                keyManager.getAlgoType("assert"),
                keyManager.getPublicKey("assert"),      // 1 - assertionMethod
                DIDMethodType.ASSERTION_METHOD,
                did));

        // authentication 키 정보
        keyInfos.add(createKeyInfo("auth",
                keyManager.getAlgoType("auth"),
                keyManager.getPublicKey("auth"),        // 2 - authentication
                DIDMethodType.AUTHENTICATION,
                did));

        // keyagreement 키 정보
        keyInfos.add(createKeyInfo("keyagree",
                keyManager.getAlgoType("keyagree"),
                keyManager.getPublicKey("keyagree"),    // 4 : keyagreement
                DIDMethodType.KEY_AGREEMENT,
                did));


        // capabilityInvocation 키 정보
        keyInfos.add(createKeyInfo("invoke",
                keyManager.getAlgoType("invoke"),
                keyManager.getPublicKey("invoke"),
                DIDMethodType.CAPABILITY_INVOCATION,          // 8 : capabilityInvocation
                did));

        // 3. DID 문서 생성. service 정보 필요시 객체 생성하여 추가(addServiceTest 메소드 참고)
        didManager.makeDIDDocument(did, keyInfos, null);

        didManager.saveToFile(didManager.getDIDDocument().toJson());

        // 블록체인에 DidDoc 저장
        LadgerMock.getInstance().setHolderDidDoc(didManager.getDIDDocument().toJson());

//        String DidDocJson = didManager.loadToFile();
//        DIDDocument didTest = GsonWrapper.getGson().fromJson(DidDocJson, DIDDocument.class);
    }


    void generateWalletAndUnlock() throws IWException {

        if (keyManager != null) return;
        keyManager = new IWKeyManager("./i.wallet");
        Sha256 hash = Sha256.from("password".getBytes());
        char[] key = hash.toString().toCharArray();

        if (!keyManager.isConnect()) {
            keyManager.unlock(key, new IWKeyManagerInterface.OnConnectListener() {
                @Override
                public void onSuccess() {
                    System.out.println("onSuccess");
                }

                @Override
                public void onFail(String errCode) {
                    System.out.println("onFail");
                }

                @Override
                public void onCancel() {
                    System.out.println("onCancel");
                }
            });
        }
    }


    public VcResult issueVC() throws Exception {
        System.out.println("issueVC");

        DIDDocument issuerDids = new DIDDocument(issuerDidDoc);
        Schema schema = new Schema(IssuerConstants.schema);

        schema.setId("default schema");
        Map<String, ClaimInfo> privacy = new HashMap<String, ClaimInfo>();

        ClaimInfo claimValue = new ClaimInfo();
        claimValue.setCode("das.v1.name");
        claimValue.setValue("김상준");
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

        // user didDoc조회
        DIDDocument userDidDocument = GsonWrapper.getGson().fromJson(LadgerMock.getInstance().getHolderDidDoc(), DIDDocument.class);

        VCManager vcManager = new VCManager();
        VcResult holderVcResult = vcManager.issueVc(issueVcParam, userDidDocument.getId(), SubjectType.USER);

        System.out.println("vc	: " + holderVcResult.getVerifiableCredentialWithoutSign().toJson());
        //////////////////////////////////////////////////////////////////////////////////////////////////
        //VC 서명 하드코딩
        List<Proof> proofs = new ArrayList<>();
        Proof proof = new Proof();
        List<String> proofValueList = new ArrayList<>();
        String value1 = "z3ma7uD2Sh7ac2rKHXQieJ6UoYKrgK7MsPrf4b8aGsEHbVFX48GJFosTbK6J484UNSAFapjCvbV5cdzScjuWcgRrj7";
        proofValueList.add(value1);
        String value2 = "z3qvhPX13ZwiPVRdaEgpkm8vuUVmBSUuWh34hETnCV71kV6LggHtD4AtMZMNwPKsqtUBaoHdAZyBorYsriq8xu94rn";
        proofValueList.add(value2);
        proof.setProofValueList(proofValueList);
        proof.setType("Secp256r1VerificationKey2018");
        proof.setCreated("2024-01-18T02:37:23");
        proof.setProofPurpose("assertionMethod");
        proof.setVerificationMethod("did:omn:issuer#assert1");
        proofs.add(proof);
        holderVcResult.getVerifiableCredentialWithoutSign().setProof(proofs);
        //////////////////////////////////////////////////////////////////////////////////////////////////
        return holderVcResult;
    }


    private void deleteFile(String fileName) {
        File file = new File(fileName);

        if (file.exists() && file.canRead()) {
            boolean delete = file.delete();
            System.out.printf("fileName: %10s delete: %s%n", fileName, delete);
        }
    }

    private KeyInfo createKeyInfo(String keyId, String algoType, String publicKey,
                                  DIDMethodType method, String controllerDid) {
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.setKeyId(keyId);
        keyInfo.setAlgoType(algoType);
        keyInfo.setPublicKey(publicKey);
        keyInfo.setMethodType(method.getRawValue());
        keyInfo.setController(controllerDid);

        return keyInfo;
    }

}
