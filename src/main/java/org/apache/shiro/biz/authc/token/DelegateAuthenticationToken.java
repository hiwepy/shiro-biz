package org.apache.shiro.biz.authc.token;

import java.io.Serializable;


public interface DelegateAuthenticationToken extends Serializable {

	String getUsername();
	 
	char[] getPassword();

	String getHost();

	boolean isRememberMe();
	
}
