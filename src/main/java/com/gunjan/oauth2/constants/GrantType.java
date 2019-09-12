package com.gunjan.oauth2.constants;

public enum GrantType {

    CLIENT_CREDENTIALS("client_credentials"),
    REFRESH_TOKEN("refresh_token"),
    PASSWORD("password"),
    AUTHORIZATION_CODE("authorization_code"),
    IMPLICIT("implicit");

    String grantType;

    private GrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getGrantType() {
        return grantType;
    }

}
