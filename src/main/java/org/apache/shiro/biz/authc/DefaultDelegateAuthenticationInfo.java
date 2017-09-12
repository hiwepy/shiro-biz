package org.apache.shiro.biz.authc;

@SuppressWarnings("serial")
public class DefaultDelegateAuthenticationInfo implements DelegateAuthenticationInfo {

	private final Object principal;
	private final Object credentials;
	
	public DefaultDelegateAuthenticationInfo(Object principal, Object credentials) {
		super();
		this.principal = principal;
		this.credentials = credentials;
	}
	
	@Override
	public Object getPrincipal() {
		return this.principal;
	}
	
	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public String getCredentialsSalt() {
		return null;
	}
}
