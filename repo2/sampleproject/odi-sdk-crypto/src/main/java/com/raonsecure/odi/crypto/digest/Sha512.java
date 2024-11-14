package com.raonsecure.odi.crypto.digest;

import com.google.common.base.Preconditions;
import com.google.common.primitives.Ints;
import com.raonsecure.oid.crypto.encoding.Base16;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha512 implements Comparable<Sha512> {

	public static final int HASH_LENGTH = 64;

	public static final Sha512 ZERO_HASH = new Sha512(new byte[HASH_LENGTH]);

	final private byte[] mHashBytes;

	@SuppressWarnings("unused")
	public Sha512(byte[] bytes) {
		Preconditions.checkArgument(bytes.length == HASH_LENGTH);
		
		if(bytes != null){
			this.mHashBytes = new byte[bytes.length];
			System.arraycopy(bytes, 0, this.mHashBytes, 0, bytes.length);
		}
		else{
			this.mHashBytes = null;
		}
		
	}

	public static Sha512 from(byte[] data) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-512");
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // cannot happen
		}

		digest.update(data, 0, data.length);

		return new Sha512(digest.digest());
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

	public int compareTo(Sha512 o) {
		for (int i = 0; i < HASH_LENGTH; i++) {
			byte myByte = mHashBytes[i];
			byte otherByte = o.mHashBytes[i];

			final int compare = Ints.compare(myByte, otherByte);
			if (compare != 0)
				return compare;
		}
		return 0;
	}

}
