package com.example.tas.demo.vo;

import com.google.gson.Gson;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class RequestVo {
    private String txId;
    private String serverToken;
    private String idRef;
    private Object data;

    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }
}
