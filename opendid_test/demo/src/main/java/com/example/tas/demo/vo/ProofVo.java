package com.example.tas.demo.vo;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ProofVo {
    private String created;
    private String kid;
    private String sigType;
    private String signature;
}