package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 登录类型支持
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public interface LoginTypeAuthenticationToken extends AuthenticationToken {

	public LoginType getLoginType();
	
}
