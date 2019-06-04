/*
 * Copyright (c) 2018 (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.biz.authc.token;

import org.apache.shiro.authc.UsernamePasswordToken;

/**
 * 默认的认证token
 * @author <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class DefaultAuthenticationToken extends UsernamePasswordToken
		implements CaptchaAuthenticationToken, 
		PwdStrengthAuthenticationToken, LoginTypeAuthenticationToken {

	/**
	 * 登录类型枚举；1：系统正常登录；2：外部单点登录；3：外部票据登录（通过握手秘钥等参数认证登录）
	 */
	protected LoginType loginType = LoginType.DEFAULE;

	protected int strength; // 密码强度

	protected String captcha; // 验证码
	
	public DefaultAuthenticationToken() {
		super();
	}
	
	public DefaultAuthenticationToken(final String username, final String password, final boolean rememberMe) {
		super(username, password, rememberMe);
	}
	
	public DefaultAuthenticationToken(final String username, final String password, final boolean rememberMe, String host) {
		super(username, password, rememberMe, host);
	}
	
	public DefaultAuthenticationToken(final String username, final String password, final String captcha, final String host) {
		super(username, password, host);
		this.captcha = captcha;
	}
	
	public DefaultAuthenticationToken(final String username, final String password, final String captcha, final boolean rememberMe, final String host ) {
		super(username, password, rememberMe, host);
		this.captcha = captcha;
	}
	
	public DefaultAuthenticationToken(final String username, final char[] password, final boolean rememberMe) {
		super(username, password, rememberMe);
	}
	
	public DefaultAuthenticationToken(final String username, final char[] password, final boolean rememberMe, String host) {
		super(username, password, rememberMe, host);
	}
	
	public DefaultAuthenticationToken(final String username, final char[] password, final String captcha, final String host) {
		super(username, password, host);
		this.captcha = captcha;
	}
	
	public DefaultAuthenticationToken(final String username, final char[] password, final String captcha, final boolean rememberMe, final String host) {
		super(username, password, rememberMe, host);
		this.captcha = captcha;
	}
	
	public int getStrength() {
		return strength;
	}

	public void setStrength(int strength) {
		this.strength = strength;
	}

	public String getCaptcha() {
		return captcha;
	}

	public void setCaptcha(String captcha) {
		this.captcha = captcha;
	}

	public LoginType getLoginType() {
		return loginType;
	}

	public void setLoginType(LoginType loginType) {
		this.loginType = loginType;
	}

	@Override
	public Object getPrincipal() {
		return getUsername();
	}

	@Override
	public Object getCredentials() {
		return getPassword();
	}

	@Override
	public String toString() {
		return "DefaultAuthenticationToken [username=" + getUsername() + ", host="
				+ getHost() + ", rememberMe=" + isRememberMe() + "]";
	}

}
