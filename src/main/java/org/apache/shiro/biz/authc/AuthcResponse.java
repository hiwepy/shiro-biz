package org.apache.shiro.biz.authc;

import java.util.ArrayList;

/**
 * Auth response for interacting with client.
 */
public class AuthcResponse {
	
	private static final String RT_SUCCESS = "success";
	private static final String RT_FAIL = "fail";
	private static final String RT_ERROR = "error";
	private static final String RT_LOGOUT = "logout";
	
    private final String code;
    
    private final String status;
	
    private final String msg;
    
    private final Object data;

    protected AuthcResponse(final String code, final String status, final String msg) {
        this.code = code;
        this.status = status;
        this.msg = msg;
        this.data = new ArrayList<>();
    }
    
    protected AuthcResponse(final String code, final String status, final String msg, final Object data) {
        this.code = code;
        this.status = status;
        this.msg = msg;
        this.data = data;
    }
     
    public static AuthcResponse success(final String msg) {
        return success(AuthcResponseCode.SC_AUTHC_SUCCESS.getCode(), msg);
    }
    
    public static AuthcResponse success(final int code, final String msg) {
        return success(String.valueOf(code), msg);
    }
    
    public static AuthcResponse success(final String code, final String msg) {
        return new AuthcResponse(code, RT_SUCCESS, msg);
    }
    
    public static AuthcResponse success(final Object data) {
        return of(AuthcResponseCode.SC_AUTHC_SUCCESS.getCode(), RT_SUCCESS,  data);
    }
    
    public static AuthcResponse fail(final String msg) {
        return fail(AuthcResponseCode.SC_AUTHC_FAIL.getCode(), msg);
    }
    
    public static AuthcResponse fail(final int code, final String msg) {
        return fail(String.valueOf(code), msg);
    }
    
    public static AuthcResponse fail(final String code, final String msg) {
        return new AuthcResponse(code, RT_FAIL, msg);
    }
    
    public static AuthcResponse error(final String msg) {
        return error(AuthcResponseCode.SC_AUTHC_ERROR.getCode(), msg);
    }
    
    public static AuthcResponse error(final int code, final String msg) {
        return error(String.valueOf(code), msg);
    }
    
    public static AuthcResponse error(final String code, final String msg) {
        return new AuthcResponse(code, RT_ERROR,  msg);
    }
    
    public static AuthcResponse logout(final String msg) {
        return logout(AuthcResponseCode.SC_AUTHC_LOGOUT.getCode(), msg);
    }
    
    public static AuthcResponse logout(final int code, final String msg) {
        return logout(String.valueOf(code), msg);
    }
    
    public static AuthcResponse logout(final String code, final String msg) {
        return new AuthcResponse(code, RT_LOGOUT,  msg);
    }
    
    public static AuthcResponse of(final int code, final String status, final String msg) {
        return of(String.valueOf(code), status, msg);
    }
    
    public static AuthcResponse of(final String code, final String status, final String msg) {
    	 return of(code, status, msg, new ArrayList<>());
    }
    
    public static AuthcResponse of(final String code, final String status, final Object data) {
        return new AuthcResponse(code, status, "", data);
    }
    
    public static AuthcResponse of(final String code, final String status, final String msg, final Object data) {
        return new AuthcResponse(code, status, msg, data);
    }

	public String getCode() {
		return code;
	}

	public String getStatus() {
		return status;
	}

	public String getMsg() {
		return msg;
	}

	public Object getData() {
		return data;
	}
    
}
