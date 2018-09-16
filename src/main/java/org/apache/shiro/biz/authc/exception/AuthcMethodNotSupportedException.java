package org.apache.shiro.biz.authc.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class AuthcMethodNotSupportedException extends AuthenticationException {

    public AuthcMethodNotSupportedException(String msg) {
        super(msg);
    }
    
}
