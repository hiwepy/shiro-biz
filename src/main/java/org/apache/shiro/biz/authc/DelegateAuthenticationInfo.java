package org.apache.shiro.biz.authc;

import java.io.Serializable;

public interface DelegateAuthenticationInfo extends Serializable{

	Object getPrincipal(); //身份

	Object getCredentials(); //凭据 

	String getCredentialsSalt(); //盐 
	
}
