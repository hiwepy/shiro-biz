package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 
 * @className	： UsertypeAuthenticationToken
 * @description	： 用户类型支持
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午9:45:44
 * @version 	V1.0
 */
public interface UsertypeAuthenticationToken extends AuthenticationToken {

	String getUserType();
	
}
