package org.apache.shiro.biz.authc;

import java.util.ArrayList;

/**
 * Auth response for interacting with client.
 */
public class AuthcResponse {
	
    private final String code;
	
    private final String msg;
    
    private final Object data;

    protected AuthcResponse(final String code, final String msg) {
        this.code = code;
        this.msg = msg;
        this.data = new ArrayList<>();
    }
    
    protected AuthcResponse(final String code, final String msg, final Object data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
    
    public static AuthcResponse of(final String code, final String msg) {
        return new AuthcResponse(code, msg);
    }

    public static AuthcResponse of(final String code, final String msg, final Object data) {
        return new AuthcResponse(code, msg, data);
    }

	public String getCode() {
		return code;
	}

	public String getMsg() {
		return msg;
	}

	public Object getData() {
		return data;
	}
    
}
