
package com.raonsecure.odi.agent.data;


import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.util.GsonWrapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Logo extends IWObject {

	/**
	 *
	 * (Required)
	 *
	 */
	@SerializedName("type")
	@Expose
	private Type type;

	/**
	 *
	 * (Required)
	 *
	 */
	@SerializedName("data")
	@Expose
	private String data;

	/**
	 *
	 * (Required)
	 *
	 */
	public Type getType() {
		return type;
	}

	/**
	 *
	 * (Required)
	 *
	 */
	public void setType(Type type) {
		this.type = type;
	}

	/**
	 *
	 * (Required)
	 *
	 */
	public String getData() {
		return data;
	}

	/**
	 *
	 * (Required)
	 *
	 */
	public void setData(String data) {
		this.data = data;
	}

	public void setDataUrl(String filePath,String imageMimetype) {
		File file = new File(filePath);
		if (file.exists()) {
			setType(Type.DATA_URL);

			String data = "data:" + imageMimetype + ";base64,";
			byte[] bytes = readBytesFromFile(file);

//			if (bytes != null) {
//				data = data + new String(org.spongycastle.util.encoders.Base64.encode(bytes));
//				setData(data);
//			}
		}
	}

	public void setUrl(String url) {
		setType(Type.URL);
		setData(url);
	}

	private static byte[] readBytesFromFile(File file) {

		FileInputStream fileInputStream = null;
		byte[] bytesArray = null;

		try {

			bytesArray = new byte[(int) file.length()];

			// read file into bytes[]
			fileInputStream = new FileInputStream(file);
			fileInputStream.read(bytesArray);

		}
		catch (IOException e) {
//			e.printStackTrace();
		}
		finally {
			if (fileInputStream != null) {
				try {
					fileInputStream.close();
				}
				catch (IOException e) {
//					e.printStackTrace();
				}
			}

		}

		return bytesArray;

	}

	public enum Type {

		@SerializedName("dataURL")
		DATA_URL("dataURL"), URL("URL");
		private final String value;

		private final static Map<String, Type> CONSTANTS = new HashMap<String, Type>();

		static {
			for (Type c : values()) {
				CONSTANTS.put(c.value, c);
			}
		}

		private Type(String value) {
			this.value = value;
		}

		@Override
		public String toString() {
			return this.value;
		}

		public String value() {
			return this.value;
		}

		public static Type fromValue(String value) {
			Type constant = CONSTANTS.get(value);
			if (constant == null) {
				throw new IllegalArgumentException(value);
			}
			else {
				return constant;
			}
		}

	}

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		Logo obj = gson.fromJson(val, Logo.class);
		type = obj.type;
		data = obj.data;
	}

}
