package com.raonsecure.odi.wallet;


public final class OmniVersion {
	// Based on https://stackoverflow.com/questions/2469922/generate-a-version-java-file-in-maven

	/** This field is automatically populated by Maven when a build is triggered */
	public static final String VERSION = "${project.version}";
	public static final String NAME = "${project.artifactId}";
	
	public static String getOmniEntSDKVersion() {
		return VERSION;
	}

	private OmniVersion() {
	}
}
