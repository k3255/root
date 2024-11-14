package com.example.tas.demo.vo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class VcPropileVo {
    private String signer;
    private String schemaId;
    private String schemaName;
    private ProofVo proof;

}