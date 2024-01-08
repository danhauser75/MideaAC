package org.openhab.binding.mideaac.internal.security;

public class TokenKey {
    String token;
    String key;

    public TokenKey(String token, String key) {
        super();
        this.token = token;
        this.key = key;
    }

    public String getToken() {
        return token;
    }

    public String getKey() {
        return key;
    }
}
