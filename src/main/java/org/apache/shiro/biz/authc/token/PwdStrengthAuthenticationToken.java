package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 
 * @className	： StrengthAuthenticationToken
 * @description	： 密码强度支持
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午9:48:34
 * @version 	V1.0
 */
public interface PwdStrengthAuthenticationToken extends AuthenticationToken {

	public int getStrength();
	
}
