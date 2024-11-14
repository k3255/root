package com.raonsecure.odi.agent.util;

import com.raonsecure.odi.agent.data.did.DIDDocument;

import java.io.*;

public class IWDIDFile {

    private String path;

    private DIDDocument data;

    private final static String DID_DOCUMENT_FILE_EXTENSION_NAME	= ".did";

    public IWDIDFile(String pathWithName) {

        String ext = null;
        int i = pathWithName.lastIndexOf('.');

        if (i > 0 &&  i < pathWithName.length() - 1) {
            ext = pathWithName.substring(i).toLowerCase();
        }

        if(ext == null || !ext.contentEquals(DID_DOCUMENT_FILE_EXTENSION_NAME)) {
            pathWithName = pathWithName + DID_DOCUMENT_FILE_EXTENSION_NAME;
        }

        path = pathWithName;
    }

    public boolean isExist() {
        File f = new File(path);
        return f.exists();
    }

    public void delete() {
        File f = new File(path);
        if (f.exists() ) {
            f.delete();
        }
    }


    public void write(String data) throws IOException {
        File file = new File(path);

        FileWriter fw = null;
        try {
            fw = new FileWriter(file);
            fw.write(data);
//            fw.close();
        }
        finally{

            fw.close();

        }
    }

    public DIDDocument getData() {
        try {
            load();
        } catch (IOException e) {
            // TODO Auto-generated catch block
//			e.printStackTrace();
        }
        return data;
    }

    public String getFilePath() {
        return path;
    }

    private IWDIDFile load() throws IOException {

        BufferedReader br = null;
        FileReader fr = null;
        try {
            // java.io
            File file = new File(path);
//            FileReader fr = new FileReader(file);
//            BufferedReader br = new BufferedReader(fr);
            fr = new FileReader(file);
            br = new BufferedReader(fr);
            StringBuffer buf = new StringBuffer();
            String line = "";
            while((line = br.readLine()) != null){
                buf.append(line);
            }

            data = new DIDDocument();
            data.fromJson(buf.toString());


            // java.nio (기존)
            // - android 7.0 (API25) 미지원
            // - android 8.0 (API26) 부터추가
//	    	byte[] bytes = Files.readAllBytes(Paths.get(path));
//	    	data = new DIDs();
//	    	data.fromJson(new String(bytes));
        } finally {
            br.close();
            fr.close();
        }
        return this;
    }
}
