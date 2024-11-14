package com.raonsecure.odi.agent.data.vc;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.raonsecure.odi.agent.data.IWObject;
import com.raonsecure.odi.agent.data.did.Proof;
import com.raonsecure.odi.agent.util.GsonWrapper;
import com.raonsecure.odi.agent.util.StringUtils;
import com.raonsecure.odi.crypto.exception.CryptoException;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerifiableCredential extends IWObject {

	@SerializedName("@context")
	@Expose
	private List<String> context;
	
	@SerializedName("id")
	@Expose
	private String id;

	@SerializedName("type")
	@Expose
	private List<String> type;
	
	@SerializedName("issuer")
	@Expose
	private Issuer issuer;

	@SerializedName("issuanceDate")
	@Expose
	private String issuanceDate;

	@SerializedName("expirationDate")
	@Expose
	private String expirationDate;

	@SerializedName("credentialSubject")
	@Expose
	private CredentialSubject credentialSubject;
	
	@SerializedName("evidence")
	@Expose
	private List<Evidence> evidence;
	
	@SerializedName("evidenceLevel")
	@Expose
	private String evidenceLevel;
	
	@SerializedName("schema")
	@Expose
	private Schema schema;
	
	@SerializedName("language")
	@Expose
	private String language = "ko";
	
	@SerializedName("encoding")
	@Expose
	private String encoding = "UTF-8";
	
	@SerializedName("proof")
	@Expose
    private List<Proof> proof;
	// 신규 format
	@SerializedName("formatVersion")
	@Expose
	private String formatVersion = "1.0";
	
	public void setContext() {
		ArrayList<String> contextList = new ArrayList<String>();
		contextList.add("https://www.w3.org/2018/credentials/v1");
		this.context = contextList;
	}
	
	public void setContext(List<String> context) {
		ArrayList<String> contextList = new ArrayList<String>(context);
		contextList.add(0, "https://www.w3.org/2018/credentials/v1");
		this.context = contextList;
	}

	public void setId() {
		if (StringUtils.isEmpty(this.id)) {
			this.id = UUID.randomUUID().toString();
		}
	}
	
	public void setIssuanceDate(String issuanceDate) {
		this.issuanceDate = issuanceDate;
	}
	
	public void setIssuanceDate(ZonedDateTime issuanceDate) {
		this.issuanceDate = dateToString(issuanceDate);
	}
	
	public String getIssuanceDate() {
		return this.issuanceDate;
	}
	
	public ZonedDateTime getIssuanceDateObject() {
		return stringToDate(this.issuanceDate);
	}

	public ZonedDateTime getExpirationDateObject() {
		return stringToDate(this.expirationDate);
	}

	public void setExpirationDate(String expires) {
		this.expirationDate = expires;
	}
	
	public void setExpirationDate(ZonedDateTime expires) {
		this.expirationDate = dateToString(expires);
	}

	@Override
	public void fromJson(String val) {
		GsonWrapper gson = new GsonWrapper();
		VerifiableCredential obj = gson.fromJson(val, VerifiableCredential.class);
		context = obj.getContext();
		id = obj.getId();
		type = obj.getType();
		issuer = obj.getIssuer();
		issuanceDate = obj.getIssuanceDate();
		expirationDate = obj.getExpirationDate();
		credentialSubject = obj.getCredentialSubject();
		evidence = obj.getEvidence();
		evidenceLevel = obj.getEvidenceLevel();
		proof = obj.getProof();		
		schema = obj.getSchema();
		language = obj.getLanguage();
		encoding = obj.getEncoding();		
		formatVersion = obj.getFormatVersion();
	}

	public static final DateTimeFormatter DATE_FROMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

	public static String dateToString(ZonedDateTime date) {
		return DATE_FROMAT.format(date);
	}

	public static ZonedDateTime stringToDate(String date) {
		LocalDateTime parsedDateTime = LocalDateTime.parse(date);
		ZonedDateTime zonedDateTime = ZonedDateTime.of(parsedDateTime, ZoneOffset.UTC);
		return zonedDateTime;
	}
}

