package com.raonsecure.odi.crypto.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import com.google.common.base.Preconditions;
import com.raonsecure.oid.crypto.encoding.Base16;

/**
 * represents the result of a SHA256 hashing operation prefer to use the static factory
 * methods.
 */
public class Sha256 {

	public static final int HASH_LENGTH = 32;

	public static final Sha256 ZERO_HASH = new Sha256(new byte[HASH_LENGTH]);

	final private byte[] mHashBytes;

	/**
	 * create Sha256 from raw hash bytes.
	 * @param bytes
	 */
	@SuppressWarnings("unused")
	public Sha256(byte[] bytes) {
		Preconditions.checkArgument(bytes.length == HASH_LENGTH);
		
		if(bytes != null){
			this.mHashBytes = new byte[bytes.length];
			System.arraycopy(bytes, 0, this.mHashBytes, 0, bytes.length);
		}
		else{
			this.mHashBytes = null;
		}
		
	}

	public static MessageDigest getSha256Digest() {
		try {
			return MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // cannot happen
		}
	}

	public static Sha256 from(byte[] data) {
		MessageDigest digest;
		digest = getSha256Digest();
		digest.update(data, 0, data.length);
		return new Sha256(digest.digest());
	}

	public static Sha256 from(byte[] data, int offset, int length) {
		MessageDigest digest;
		digest = getSha256Digest();
		digest.update(data, offset, length);
		return new Sha256(digest.digest());
	}

	public static Sha256 from(byte[] data1, byte[] data2) {
		MessageDigest digest;
		digest = getSha256Digest();
		digest.update(data1, 0, data1.length);
		digest.update(data2, 0, data2.length);
		return new Sha256(digest.digest());

	}

	public static Sha256 doubleHash(byte[] data, int offset, int length) {
		MessageDigest digest;
		digest = getSha256Digest();
		digest.update(data, offset, length);
		return new Sha256(digest.digest(digest.digest()));
	}

	@Override
	public boolean equals(Object other) {
		if (other == this) {
			return true;
		}
		if (!(other instanceof Sha256))
			return false;
		return Arrays.equals(mHashBytes, ((Sha256) other).mHashBytes);
	}

	@Override
	public String toString() {
		return Base16.toHex(mHashBytes);
	}

	public byte[] getBytes() {
		
		if(mHashBytes == null){
			return null;
		}
		byte [] hash = new byte[mHashBytes.length];
		System.arraycopy(mHashBytes, 0, hash, 0, mHashBytes.length);
		
//		return mHashBytes;
		return hash;
	}

	public boolean equalsFromOffset(byte[] toCompareData, int offsetInCompareData,
			int len) {
		if ((null == toCompareData) || (offsetInCompareData < 0) || (len < 0)
				|| (mHashBytes.length <= len)
				|| (toCompareData.length <= offsetInCompareData)) {
			return false;
		}

		for (int i = 0; i < len; i++) {

			if (mHashBytes[i] != toCompareData[offsetInCompareData + i]) {
				return false;
			}
		}

		return true;
	}

	public int length() {
		return HASH_LENGTH;
	}


}
