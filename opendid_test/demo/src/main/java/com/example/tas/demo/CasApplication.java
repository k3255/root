package com.example.tas.demo;

import com.example.tas.demo.message.Data;
import com.example.tas.demo.message.MessageConverter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CasApplication {

	public static void main(String[] args) {
		SpringApplication.run(CasApplication.class, args);
		// 신규문법 파싱 테스트

		System.out.println("did doc : " + MessageConverter.convertToJSON(Data.DIDDocument));
		System.out.println("vc : " + MessageConverter.convertToJSON(Data.vc));
		System.out.println("vp : " + MessageConverter.convertToJSON(Data.vp));
		System.out.println("vc_claim : " + MessageConverter.convertToJSON(Data.vcClaim));
		System.out.println("vc_attach : " +  MessageConverter.convertToJSON(Data.vcAttach));

	}

}
