package org.apache.shiro.biz.realm;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.authc.token.JWTAuthenticationToken;

public class JWTPrincipalRealm extends AbstractPrincipalRealm{

	@Override
	protected DelegateAuthenticationToken createDelegateAuthenticationToken(AuthenticationToken token) {
		return (JWTAuthenticationToken) token;
	}

}
