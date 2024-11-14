package mock;

public class IssuerConstants {

    public final static String schema = "{\"claims\":[{\"attribute\":{\"hideValue\":true,\"location\":\"inline\",\"type\":\"text\"},\"caption\":\"이름\",\"code\":\"das.v1.name\",\"mandatory\":true},"
            + "{\"attribute\":{\"hideValue\":true,\"location\":\"remote\",\"type\":\"text\"},\"caption\":\"url\",\"code\":\"das.v1.url\",\"mandatory\":true}],\"id\":\"issuer.schema\",\"name\":\"test schema\",\"version\":\"1.0\"}";

    public final static String issuerDidDoc = "{\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"assertionMethod\":[\"did:omn:issuer#assert1\"],\"authentication\":[\"did:omn:issuer#auth1\"],\"capabilityInvocation\":[\"did:omn:issuer#invoke\"],\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer\",\"keyAgreement\":[\"did:omn:issuer#keyagree\"],\"updated\":\"2024-01-08T02:20:25\",\"verificationMethod\":[{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#assert1\",\"publicKeyMultibase\":\"zf7v4m3HJBoNHfMw1Gjn24Sz8eP88EUJeCNZbvWKXHDQg\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#auth1\",\"publicKeyMultibase\":\"zfgCVCvkaNTunJ9WpYAW271AXFRMMs7wyqstrqw75eEJd\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#keyagree\",\"publicKeyMultibase\":\"z27XTBXV64KLUJP4G2q8Lcd7G1315DLCyE9puc58K8HYQg\",\"status\":\"valid\",\"type\":\"Secp256r1KeyAgreementKey2019\"},{\"authType\":1,\"controller\":\"did:omn:issuer\",\"id\":\"did:omn:issuer#invoke\",\"publicKeyMultibase\":\"z23oDE9R9MAZxTrqvemm4YBGsEDhSfTvaW6baqtKmjLdAm\",\"status\":\"valid\",\"type\":\"Secp256r1VerificationKey2018\"}]}";

}
