package com.example.tas.demo.vo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class VpPropileVo {
    private String signer;
    private String srvId;
    private String srvName;
    private String srvDesc;
    private ProofVo proof;
}