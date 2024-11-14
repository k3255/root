package com.raonsecure.odi.agent.util;

public class StringUtils {

	public static boolean isEmpty(CharSequence data) {
		return (null == data) || (data.length() <= 0);
	}

}