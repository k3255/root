package com.raonsecure.odi.crypto.util;

import com.raonsecure.odi.crypto.enums.MultiBaseEnum;
import com.raonsecure.odi.crypto.exception.CryptoErrorCode;
import com.raonsecure.odi.crypto.exception.CryptoException;
import com.raonsecure.oid.crypto.encoding.Base16;
import com.raonsecure.oid.crypto.encoding.Base16Upper;
import com.raonsecure.oid.crypto.encoding.Base58;
import com.raonsecure.oid.crypto.encoding.Base64;

public class MultiBase {
		
	public static String encode(byte[] source, MultiBaseEnum baseType) throws CryptoException {
		String character = baseType.getCharacter();

        switch (baseType){
            case Base16:
            	String enc16Data = Base16.toHex(source);
            	
            	StringBuilder sb16 = new StringBuilder(enc16Data);
            	sb16.insert(0, character);

           		return new String(sb16);
            case Base16upper:
            	String enc16UpperData = Base16Upper.toHex(source);
            	
            	StringBuilder sb16Upper = new StringBuilder(enc16UpperData);
            	sb16Upper.insert(0, character);
            	
           		return new String(sb16Upper);
            case Base58btc:
            	String enc58Data = Base58.encode(source);
            	
            	StringBuilder sb58 = new StringBuilder(enc58Data);
            	sb58.insert(0, character);
       
           		return new String(sb58);
            case Base64url:
            	String enc64UrlData = Base64.encodeUrlString(source);
            	
            	StringBuilder sb64Url = new StringBuilder(enc64UrlData);
            	sb64Url.insert(0, character);

           		return new String(sb64Url);
            case Base64:
            	String enc64Data = Base64.encodeToString(source, Base64.DEFAULT);
            	
            	StringBuilder sb64 = new StringBuilder(enc64Data);
            	sb64.insert(0, character);

           		return new String(sb64);
            default:
            	throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_INVALID_ENCODING_TYPE);
        }
	}
	

	public static byte[] decode(String multibase) throws CryptoException {

		if (multibase == null || multibase.length() < 2) {
			return null;
		}
		String firstString = multibase.substring(0, 1);
		String remainString = multibase.substring(1);
		
		MultiBaseEnum baseType = getMultibaseEnum(firstString);
		if (baseType == null) {
			return null;
		}
		switch (baseType) {
		case Base16:
			return Base16.toBytes(remainString);
        case Base16upper:
            return Base16Upper.toBytes(remainString);
		case Base58btc:
			return Base58.decode(remainString);
		case Base64url:
			return Base64.decodeUrl(remainString);
		case Base64:
			return Base64.decode(remainString, Base64.DEFAULT);
		default:
			throw new CryptoException(CryptoErrorCode.ERR_CODE_CRYPTOMANAGER_INVALID_DECOGING_TYPE);
		}
	}


	private static MultiBaseEnum getMultibaseEnum(String firstString) {
        for (MultiBaseEnum baseType : MultiBaseEnum.values()) {
            if (baseType.getCharacter().equals(firstString)) {
               return baseType;
            }
        }
        return null;
	}
}