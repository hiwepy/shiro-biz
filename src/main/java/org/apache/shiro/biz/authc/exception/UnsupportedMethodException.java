package org.apache.shiro.biz.authc.exception;

import org.apache.shiro.authc.AuthenticationException;

@SuppressWarnings("serial")
public class UnsupportedMethodException extends AuthenticationException {

    public UnsupportedMethodException(String msg) {
        super(msg);
    }
    
}
