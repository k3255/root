package com.example.tas.demo.message;

public class Data {
    public static String DIDDocument = "{\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Meta\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + array(url)   \"@context\"   : \"JSON-LD context\", value([\"https://www.w3.org/ns/did/v1\"])\n" +
            "    + did          \"id\"         : \"DID owner's did\"\n" +
            "    + did          \"controller\" : \"DID controller's did\"\n" +
            "    + utc_datetime \"created\"    : \"created datetime\"\n" +
            "    + utc_datetime \"updated\"    : \"last updated datetime\"\n" +
            "    + did_version  \"versionId\"  : \"DID version id\"\n" +
            "    - bool         \"deactivated\": \"true: deactivated, false: activated\", default(false)\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // DID key list\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + array(object) \"verificationMethod\": \"list of DID key with public key value\", min_count(1)\n" +
            "    {\n" +
            "        + key_id       \"id\"                : \"key id\"\n" +
            "        + DID_KEY_TYPE \"type\"              : \"key type\"\n" +
            "        + did          \"controller\"        : \"key controller's did\"\n" +
            "        + multibase    \"publicKeyMultibase\": \"public key value\"\n" +
            "        //--- 이하 비표준 항목 ---\n" +
            "        + AUTH_TYPE    \"authType\"          : \"required authentication to use the key\"\n" +
            "        + KEY_STATUS   \"status\"            : \"key status\"\n" +
            "    }\n" +
            "\n" +
            "    // 용도별 키 목록\n" +
            "    // - 모든 'key_id'는 '~/verificationMethod[]/id'에 선언되어 있어야 함\n" +
            "    - array(key_id) \"assertionMethod\"     : \"list of Assertion key id\", emptiable(false)\n" +
            "    - array(key_id) \"authentication\"      : \"list of Authentication key id\", emptiable(false)\n" +
            "    - array(key_id) \"keyAgreement\"        : \"list of Key Agreement key id\", emptiable(false)\n" +
            "    - array(key_id) \"capabilityInvocation\": \"list of Capability Invocation key id\", emptiable(false)\n" +
            "    - array(key_id) \"capabilityDelegation\": \"list of Capability Delegation key id\", emptiable(false)\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Service endpoint\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    - array(object) \"service\": \"list of service\", min_count(1)\n" +
            "    {\n" +
            "        + service_id   \"id\"             : \"service id\"  // ex: \"did:omn:user#homepage\"\n" +
            "        + SERVICE_TYPE \"type\"           : \"service type\"\n" +
            "        + array(url)   \"serviceEndpoint\": \"list of URL to the service\", min_count(1)\n" +
            "    }\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Role - 비표준 항목\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    - object \"role\": \"role of the DID owner\", emptiable(false)\n" +
            "    {\n" +
            "        + ROLE_TYPE     \"type\"   : \"role type\"\n" +
            "        - ROLE_SUB_TYPE \"subType\": \"sub type for 'provider' role\"\n" +
            "            , default(null)  // type == \"provider\" 인 경우 필수\n" +
            "    }\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Proof - 비표준 항목\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    - array(object) \"proof\": \"list of proof\", emptiable(false)\n" +
            "    {\n" +
            "        + PROOF_TYPE    \"type\"              : \"proof type\"\n" +
            "        + utc_datetime  \"created\"           : \"proof created datetime\"\n" +
            "        + key_id        \"verificationMethod\": \"key id used to create the proof\"\n" +
            "        + PROOF_PURPOSE \"proofPurpose\"      : \"proof purpose\"\n" +
            "        + multibase     \"proofValue\"        : \"proof value\"\n" +
            "    }\n" +
            "}\n";

    public static String vc = "{\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Credential Metadata\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + array(url)     \"@context\": \"JSON-LD context\", value([\"https://www.w3.org/ns/credentials/v2\"])\n" +
            "    + vc_id          \"id\"      : \"VC id\"\n" +
            "    + array(VC_TYPE) \"type\"    : \"VC 타입 목록\"\n" +
            "    + object         \"issuer\"  : \"이슈어 정보\"\n" +
            "    {\n" +
            "        + did    \"id\"  : \"이슈어 did\"\n" +
            "        - string \"name\": \"이슈어 이름\", emptiable(false)\n" +
            "    }\n" +
            "    + utc_datetime   \"issuanceDate\" : \"발급일시\"\n" +
            "    + utc_datetime   \"validFrom\"    : \"유효기간 시작 일시\"\n" +
            "    + utc_datetime   \"validUntil\"   : \"유효기간 종료 일시\"\n" +
            "    + ENCODING       \"encoding\"     : \"VC 파일 인코딩\", default(\"UTF-8\")\n" +
            "    + string         \"formatVersion\": \"VC 형식 버전\", default(\"1.0\")\n" +
            "    + LANGUAGE       \"language\"     : \"VC 파일 언어 코드\"\n" +
            "    + array(object)  \"evidence\"     : \"evidence\"\n" +
            "    {\n" +
            "        - url           \"id\"      : \"해당 evidence에 대한 (추가)정보 조회를 위한 URL\"\n" +
            "        + EVIDENCE_TYPE \"type\"    : \"evidence 타입 목록\"\n" +
            "        + did           \"verifier\": \"evidence 검증자\"\n" +
            "\n" +
            "        // Evidence 타입별 데이터\n" +
            "        + choice(1)\n" +
            "        {\n" +
            "            ^ group: // when type == \"DocumentVerification\"\n" +
            "            {\n" +
            "                + string   \"evidenceDocument\": \"증거서류 명칭\"\n" +
            "                + PRESENCE \"subjectPresence\" : \"주체의 출현 방식\"\n" +
            "                + PRESENCE \"documentPresence\": \"서류의 출현 방식\"\n" +
            "                - string   $attribute        : \"서류 부가정보. 예: 면허번호\"\n" +
            "            }\n" +
            "        }\n" +
            "    }\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Claim(s)\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + object \"credentialSubject\": \"credential subject\"\n" +
            "    {\n" +
            "        + did          \"id\"    : \"subject did\"\n" +
            "        + array(claim) \"claims\": \"클레임 목록\", min_count(1)\n" +
            "    }\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Proof(s)\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + object \"proof\": \"VC에 대한 이슈어 서명\"\n" +
            "    {\n" +
            "        + PROOF_TYPE       \"type\"              : \"proof type\"\n" +
            "        + utc_datetime     \"created\"           : \"proof 생성 일시\"\n" +
            "        + key_id           \"verificationMethod\": \"proof 서명에 사용한 key id\"\n" +
            "        + PROOF_PURPOSE    \"proofPurpose\"      : \"proof purpose\", value(\"assertionMethod\")\n" +
            "        + multibase        \"proofValue\"        : \"전체 클레임에 대한 서명\"\n" +
            "        + array(multibase) \"proofValueList\"    : \"개별 클레임에 대한 서명\"\n" +
            "    }\n" +
            "}\n";

    public static String vp = "{\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Presentation Metadata\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + array(url)     \"@context\"  : \"JSON-LD context\", value([\"https://www.w3.org/ns/credentials/v2\"])\n" +
            "    + vp_id          \"id\"        : \"VP id\"\n" +
            "    + array(VP_TYPE) \"type\"      : \"VP 타입 목록\"\n" +
            "    + did            \"holder\"    : \"홀더 did\"\n" +
            "    + utc_datetime   \"validFrom\" : \"VP 유효기간 시작 일시\"\n" +
            "    + utc_datetime   \"validUntil\": \"VP 유효기간 종료 일시\"\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Verifiable Crendential(s)\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + array(object) \"verifiableCredential\": \"VC 목록\"\n" +
            "    {\n" +
            "        //--- Credential Metadata ---\n" +
            "        // VC의 모든 Metadata 포함\n" +
            "        // ...생략...\n" +
            "\n" +
            "        //--- Claim(s) ---\n" +
            "        + object \"credentialSubject\": \"credential subject\"\n" +
            "        {\n" +
            "            + did          \"id\"    : \"subject did\"\n" +
            "            // 선택된 클레임만 포함\n" +
            "            + array(claim) \"claims\": \"클레임 목록\", min_count(1)\n" +
            "        }\n" +
            "\n" +
            "        //--- Proof(s) ---\n" +
            "        + object \"proof\": \"VC에 대한 이슈어 서명\"\n" +
            "        {\n" +
            "            + PROOF_TYPE       \"type\"              : \"proof type\"\n" +
            "            + utc_datetime     \"created\"           : \"proof 생성 일시\"\n" +
            "            + key_id           \"verificationMethod\": \"proof 서명에 사용한 key id\"\n" +
            "            + PROOF_PURPOSE    \"proofPurpose\"      : \"proof purpose\", value(\"assertionMethod\")\n" +
            "            //============================================\n" +
            "            // !!!전체서명인 \"proofValue\"가 없음에 주의!!!\n" +
            "            //============================================\n" +
            "            // 선택된 클레임에 대한 개별서명만 순서대로 포함\n" +
            "            + array(multibase) \"proofValueList\"    : \"개별 클레임에 대한 서명\"\n" +
            "        }\n" +
            "    }\n" +
            "\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    // Proof(s)\n" +
            "    //---------------------------------------------------------------------------\n" +
            "    + object \"proof\": \"VP에 대한 홀더 서명\"\n" +
            "    {\n" +
            "        + PROOF_TYPE       \"type\"              : \"proof type\"\n" +
            "        + utc_datetime     \"created\"           : \"proof 생성 일시\"\n" +
            "        + key_id           \"verificationMethod\": \"proof 서명에 사용한 key id\"\n" +
            "        + PROOF_PURPOSE    \"proofPurpose\"      : \"proof purpose\", value(\"assertionMethod\")\n" +
            "        + multibase        \"proofValue\"        : \"VP에 대한 홀더 서명\"\n" +
            "    }\n" +
            "}\n";

    public static String vcClaim = "{\n" +
            "    + claim_code \"code\"     : \"클레임 코드\"\n" +
            "    + string     \"caption\"  : \"클레임 이름\"\n" +
            "    + string     \"value\"    : \"클레임 값\"\n" +
            "    - object     \"attribute\": \"클레임 속성\"\n" +
            "    {\n" +
            "        + CLAIM_TYPE   \"type\"     : \"클레임 타입\", default(\"text\")\n" +
            "        + CLAIM_FORMAT \"format\"   : \"클레임 포맷\", default(\"plain\")\n" +
            "        + bool         \"hideValue\": \"클레임 값 숨김 여부\", default(false)\n" +
            "        + LOCATION     \"location\" : \"클레임 원본 위치\", default(\"inline\")\n" +
            "    }\n" +
            "    - digest \"digestSRI\": \"클레임 값의 해시\", default(null)\n" +
            "    - object \"i18n\": \"다국어 정보. 기본언어 이외에 대해 추가\"\n" +
            "    {\n" +
            "        + object $lang: \"언어별 정보\", min_extend(1)\n" +
            "        {\n" +
            "            + string \"caption\"  : \"클레임 이름\"\n" +
            "            + string \"value\"    : \"클레임 값\"\n" +
            "            - digest \"digestSRI\": \"클레임 값의 해시\"\n" +
            "        }\n" +
            "    }\n" +
            "}\n";

    public static String vcAttach = "def object attach: \"첨부파일\"\n" +
            "{\n" +
            "    + object $attachId: \"첨부 데이터\", min_extend(1)\n" +
            "    {\n" +
            "        + multibase \"value\": \"multibase로 변환한 데이터\"\n" +
            "    }\n" +
            "    \n" +
            "    + object \"proof\": \"첨부파일에 대한 이슈어 서명\"\n" +
            "    {\n" +
            "        + PROOF_TYPE    \"type\"              : \"proof type\"\n" +
            "        + utc_datetime  \"created\"           : \"proof created datetime\"\n" +
            "        + key_id        \"verificationMethod\": \"key id used to create the proof\"\n" +
            "        + PROOF_PURPOSE \"proofPurpose\"      : \"proof purpose\", value(\"assertionMethod\")\n" +
            "        + multibase     \"proofValue\"        : \"proof value\"\n" +
            "    }\n" +
            "}";

}
