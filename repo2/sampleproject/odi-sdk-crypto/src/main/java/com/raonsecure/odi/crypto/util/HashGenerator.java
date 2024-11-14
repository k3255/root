package com.raonsecure.odi.crypto.util;

import com.raonsecure.odi.crypto.digest.Sha256;
import com.raonsecure.odi.crypto.digest.Sha384;
import com.raonsecure.odi.crypto.digest.Sha512;
import com.raonsecure.odi.crypto.enums.DigestEnum;

public class HashGenerator {

	public static byte[] generateHash(byte[] source, DigestEnum digestEnum) {

		switch (digestEnum) {

		case Sha256:
			return Sha256.from(source).getBytes();
		case Sha512:
			return Sha512.from(source).getBytes();
		case Sha384:
			return Sha384.from(source).getBytes();
		default:
			return null;
		}
	}
}
