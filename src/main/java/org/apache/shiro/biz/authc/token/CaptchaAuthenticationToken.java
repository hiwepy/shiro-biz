package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 
 * @className	： CaptchaAuthenticationToken
 * @description	： 验证码支持
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午9:26:54
 * @version 	V1.0
 */
public interface CaptchaAuthenticationToken extends AuthenticationToken {

	String getCaptcha();
	
}
