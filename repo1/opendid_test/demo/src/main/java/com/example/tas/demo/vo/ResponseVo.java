package com.example.tas.demo.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.gson.Gson;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseVo {
    private String txId;
    private int code;
    private String message;
    private Object data;

    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }
}
