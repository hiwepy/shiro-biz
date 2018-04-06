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
		implements DelegateAuthenticationToken, CaptchaAuthenticationToken, 
		PwdStrengthAuthenticationToken, LoginTypeAuthenticationToken {

	/**
	 * 登录类型枚举；1：系统正常登录；2：外部单点登录；3：外部票据登录（通过握手秘钥等参数认证登录）
	 */
	protected LoginType loginType = LoginType.DEFAULE;

	protected String userType; // 用户类型

	protected int strength; // 密码强度

	protected String captcha; // 验证码

	public DefaultAuthenticationToken() {
		super();
	}

	public DefaultAuthenticationToken(String username, String password) {
		super(username, password);
	}

	public DefaultAuthenticationToken(String username, String password, LoginType loginType) {
		super(username, password);
		this.loginType = loginType;
	}

	public DefaultAuthenticationToken(String username, char[] password) {
		super(username, password);
	}

	public DefaultAuthenticationToken(String username, char[] password, LoginType loginType) {
		super(username, password);
		this.loginType = loginType;
	}

	public DefaultAuthenticationToken(String username, String password, String captcha) {
		this(username, password != null ? password.toCharArray() : null, captcha);
	}

	public DefaultAuthenticationToken(String username, String password, String captcha, LoginType loginType) {
		this(username, password != null ? password.toCharArray() : null, captcha, loginType);
	}

	public DefaultAuthenticationToken(String username, char[] password, String captcha) {
		super(username, password);
		this.captcha = captcha;
	}

	public DefaultAuthenticationToken(String username, char[] password, String captcha, LoginType loginType) {
		super(username, password);
		this.captcha = captcha;
		this.loginType = loginType;
	}

	public DefaultAuthenticationToken(String username, String password, String userType, String captcha) {
		this(username, password != null ? password.toCharArray() : null, userType, captcha);
	}

	public DefaultAuthenticationToken(String username, char[] password, String userType, String captcha) {
		super(username, password);
		this.userType = userType;
		this.captcha = captcha;
	}

	public DefaultAuthenticationToken(String username, String password, String userType, boolean rememberMe) {
		this(username, password != null ? password.toCharArray() : null, userType, rememberMe);
	}

	public DefaultAuthenticationToken(String username, char[] password, String userType, boolean rememberMe) {
		super(username, password, rememberMe);
		this.userType = userType;
	}

	public DefaultAuthenticationToken(String username, String password, String userType, String host,
			boolean rememberMe) {
		this(username, password != null ? password.toCharArray() : null, userType, host, rememberMe);
	}

	public DefaultAuthenticationToken(String username, char[] password, String userType, String host,
			boolean rememberMe) {
		super(username, password, rememberMe, host);
		this.userType = userType;
	}

	public DefaultAuthenticationToken(String username, String password, String userType, String captcha, String host,
			boolean rememberMe) {
		this(username, password != null ? password.toCharArray() : null, userType, captcha, host, rememberMe);
	}

	public DefaultAuthenticationToken(String username, char[] password, String userType, String captcha, String host,
			boolean rememberMe) {
		this(username, password, userType, captcha, host, rememberMe, LoginType.DEFAULE);
	}

	public DefaultAuthenticationToken(String username, char[] password, String userType, String captcha, String host,
			boolean rememberMe, LoginType loginType) {
		super(username, password, rememberMe, host);
		this.userType = userType;
		this.captcha = captcha;
		this.loginType = loginType;
	}

	public String getUserType() {
		return userType;
	}

	public void setUserType(String userType) {
		this.userType = userType;
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
