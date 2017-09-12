package org.apache.shiro.biz.authc.token;

import java.io.Serializable;

public interface DelegateAuthenticationToken extends Serializable {

	String getUsername();

	String getUserType();
	
	LoginType getLoginType();

	char[] getPassword();
	
	int getStrength();

	String getCaptcha();

	String getHost();

	boolean isRememberMe();
}
