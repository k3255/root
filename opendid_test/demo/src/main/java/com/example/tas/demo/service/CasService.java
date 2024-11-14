package com.example.tas.demo.service;

import com.example.tas.demo.db.domain.Cas;
import com.example.tas.demo.db.repository.CasRepository;
import com.example.tas.demo.vo.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

@Service
public class CasService {
    @Autowired
    CasRepository tasRepository;
    public ResponseVo test(RequestVo request){
        SimpleDateFormat formatter= new SimpleDateFormat("yyyy-MM-dd 'at' HH:mm:ss z");
        Date date = new Date(System.currentTimeMillis());

        System.out.println("request : " + request.toJson() + " / " + date);
        ProofVo proof = new ProofVo();
        proof.setCreated("date");
        proof.setKid("verifyKey");
        proof.setSigType("secp256r1");
        proof.setSignature("signVal");

        VcPropileVo vcProfile = new VcPropileVo();
        vcProfile.setSigner("VC");
        vcProfile.setSchemaId("schemaId");
        vcProfile.setSchemaName("schemaName");
        vcProfile.setProof(proof);

        VpPropileVo vpProfile = new VpPropileVo();
        vpProfile.setSigner("VP");
        vpProfile.setSrvId("srvId");
        vpProfile.setSrvName("srvName");
        vpProfile.setSrvDesc("desc");
        vpProfile.setProof(proof);

        ResponseVo response1 = new ResponseVo();
        response1.setTxId("vc_tx");
        response1.setCode(0);
        response1.setMessage("succeed");
        response1.setData(vcProfile);
        System.out.println("vc response : " + response1.toJson());

        ResponseVo response2 = new ResponseVo();
        response2.setTxId("vp_tx");
        response2.setCode(0);
        response2.setMessage("succeed");
        response2.setData(vpProfile);
        System.out.println("vp response : " + response2.toJson());

        ResponseVo response3 = new ResponseVo();
        String txId = UUID.randomUUID().toString();
        response3.setTxId(txId);
        response3.setCode(0);
        response3.setMessage("succeed");
        System.out.println("trade response : " + response3.toJson());

        Cas cas = new Cas();
        cas.setTxId(txId);
        //cas.setTxId("9cb45902-4295-4da5-b92b-3bffb3eed3a0");
        //tasRepository.save(cas);

        return response3;
    }
}
