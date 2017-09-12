package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 
 * @className	： LoginTypeAuthenticationToken
 * @description	： 登录类型支持
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午9:49:31
 * @version 	V1.0
 */
public interface LoginTypeAuthenticationToken extends AuthenticationToken {

	public LoginType getLoginType();
	
}
