package org.apache.shiro.biz.authc.exception;

import org.apache.shiro.authc.AuthenticationException;

public class AuthMethodNotSupportedException extends AuthenticationException {
    private static final long serialVersionUID = 3705043083010304496L;

    public AuthMethodNotSupportedException(String msg) {
        super(msg);
    }
    
}
