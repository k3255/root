package com.example.tas.demo.message;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.tomcat.util.json.JSONParser;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class MessageConverter {

public static String convertToJSONOld() {
    //String str = "+ array(url)   \"@context\"   : \"JSON-LD context\", value([\"https://www.w3.org/ns/did/v1\"])";
    String str = "";
    StringBuilder builder = new StringBuilder();
    boolean startCut = false;
    boolean startMsg = false;
    boolean isUrl = false;
    builder.append("{");
    builder.append("\n");

    for (char c : str.toCharArray()) {
        if (c == '+' || c == '-' || c == '/') {
            startCut = true;
            startMsg = false;
        }
//
        if (startMsg) {
            builder.append(c);
        }

        if (startCut && c == '"') {
            startMsg = true;
            builder.append(c);
            //break;
        }
    }
    builder.append("}");
    String trimmedResult = builder.toString().trim();
    trimmedResult = trimmedResult.replace("\"\"", "\"");
    return trimmedResult;
    }


    public static String convertToJSON(String str){
        String[] lines = str.split("\n"); // line 단위로 자름
        StringBuilder builder = new StringBuilder();
        int cnt = 0;
        boolean isArray = false;
        for (String line : lines) {
            if (line.trim().startsWith("+") || line.trim().startsWith("-")) {
                String[] parts = line.trim().split("\"");
                if(parts[0].contains("choice")){
                    builder.append("\"choice <그룹내 선택>\":");
                    continue;
                }
                if(parts[0].contains("attribute")){
                    // 넣어야함
                    continue;
                }
                if(parts[0].contains("object")){
                    if(parts[0].contains("$")){
                        //생각해봐야함
                        builder.append("\"val\"");
                    } else {
                        builder.append("\"");
                        if (line.trim().startsWith("-"))
                            builder.append("?");
                        builder.append(parts[1]);
                        builder.append("<");
                        builder.append(parts[3]);
                        builder.append(">");
                        builder.append("\"");
                    }
                    builder.append(":");
                    if(parts[0].contains("array")){
                        builder.append("[");
                        isArray = true;
                        cnt++;
                    }
                    continue;
                }
                /////// key ///////
                builder.append("\"");
                if(line.trim().startsWith("-"))
                    builder.append("?");
                builder.append(parts[1]);
                builder.append("\"");
                builder.append(":");

                if(parts.length > 5 &&(parts[4].contains("default") || parts[4].contains("emptiable")|| parts[4].contains("value"))){
                    if(parts[0].contains("array")){
                        builder.append("[");
                        builder.append("\"");
                        builder.append(parts[5]);
                        builder.append("\"");
                        builder.append("]");
                        builder.append(",");
                    } else{
                        builder.append("\"");
                        builder.append(parts[5]);
                        builder.append("\"");
                        builder.append(",");
                    }
                    continue;
                }
                /////// value ///////
                if (parts[0].contains("array")){
                    builder.append("[");
                    builder.append("\"");
                    builder.append(parts[3]);
                    builder.append("\"");
                    builder.append("]");
                    builder.append(",");
                    continue;
                }
                builder.append("\"");
                builder.append(parts[3]);
                builder.append("\"");
                builder.append(",");
            }
            if (line.trim().startsWith("^")) {
                builder.append("\"group\":");
            }
            if (line.trim().startsWith("{") || line.trim().startsWith("}")) {
                if(builder.isEmpty()){
                    builder.append(line);
                    continue;
                }
                char currentChar = builder.charAt(builder.length() - 1);
                if(currentChar == ',')
                    builder.deleteCharAt(builder.length()-1);
                builder.append(line);

                if(line.trim().startsWith("{"))
                    cnt++;
                if(line.trim().startsWith("}")) {
                    cnt--;
                    if(cnt == 1 && isArray) {
                            builder.append("]");
                            cnt--;
                            isArray =false;
                    }
                    builder.append(",");
                }
            }
        }
        char currentChar = builder.charAt(builder.length() - 1);
        if(currentChar == ',')
            builder.deleteCharAt(builder.length()-1);

        return builder.toString().trim();
    }

    public void jsonStrTojsonObj(String jsonString){
        JsonParser jsonParser = new JsonParser();
        Object obj = null;
        try {
            obj = jsonParser.parse(jsonString); //builder.toString().trim()
            JsonObject jsonObj = (JsonObject) obj;
            Iterator i = jsonObj.keySet().iterator();

            while(i.hasNext())
            {
                String b = i.next().toString();
                System.out.println("key : " + b);
            }
        }
        catch (Exception e){
            System.out.println("jsonObject id : " + e.getMessage());
        }
    }

}
