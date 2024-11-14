package com.raonsecure.odi.crypto.enums;

public enum MultiBaseEnum {
	Base16("f"), 
	Base16upper("F"), 
	Base58btc("z"),
	Base64url("u"),
	Base64("m");

	private String character;

	MultiBaseEnum(String character) {
		this.character = character.substring(0, 1);
	}

	public String getCharacter() {
		return character;
	}
	
	public static MultiBaseEnum getByCharacter(String inputCharacter) {
        for (MultiBaseEnum value : MultiBaseEnum.values()) {
            if (value.character.equalsIgnoreCase(inputCharacter)) {
                return value;
            }
        }
        // 입력된 character에 매칭되는 값이 없을 경우 기본값으로 Base64url을 반환
        return Base64url;
    }

}
