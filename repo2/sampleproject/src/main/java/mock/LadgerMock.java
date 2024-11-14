package mock;

public class LadgerMock {

    private static LadgerMock instance;

    /** Issuer **/


    /** holder **/
    private String holderDidDoc;


    /** verifier **/




    private LadgerMock() {
        // private 생성자
    }

    public static LadgerMock getInstance() {
        if (instance == null) {
            instance = new LadgerMock();
        }
        return instance;
    }

    public void setHolderDidDoc(String didDoc) {
        holderDidDoc = didDoc;
    }

    public String getHolderDidDoc() {
        return holderDidDoc;
    }
}
