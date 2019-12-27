package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 密码强度支持
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
public interface PwdStrengthAuthenticationToken extends AuthenticationToken {

	public int getStrength();
	
}
