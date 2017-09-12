package org.apache.shiro.biz.authc;

import java.io.Serializable;

public interface DelegateAuthenticationInfo extends Serializable{

	Object getPrincipal();

	Object getCredentials();

	String getCredentialsSalt();
	
}
