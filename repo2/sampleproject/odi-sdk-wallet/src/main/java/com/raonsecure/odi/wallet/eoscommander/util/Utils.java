/*
 * Copyright (c) 2017-2018 PLACTAL.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.raonsecure.odi.wallet.eoscommander.util;

import java.io.Closeable;

import com.google.gson.GsonBuilder;

/**
 * Created by swapnibble on 2017-10-18.
 */

public class Utils {

	public static void closeSilently(Closeable c) {
		if (null != c) {
			try {
				c.close();
			}
			catch (Throwable t) {
				c = null;
			}
		}
	}

	public static long parseLongSafely(String content, int defaultValue) {
		if (null == content)
			return defaultValue;

		try {
			return Long.parseLong(content);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	public static int parseIntSafely(String content, int defaultValue) {
		if (null == content)
			return defaultValue;

		try {
			return Integer.parseInt(content);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

}
