package org.apache.shiro.biz.web;

import java.util.Locale;

public enum Parameter {
	
	/**
	 */
	HTTP_USER_NAME("http-user-name"),
	/**
	 */
	HTTP_PWD_NAME("http-pwd-name"),
	
	/**
	 */
	LOGIN_DISPATCH_URL("login-dispatch-url"),
	/**
	 */
	LOGIN_REDIRECT_URL("login-redirect-url"),
	
	/**
	 * shiro控制的缓存
	 */
	SHIRO_APPLICATION_CACHE("application-cache"),
	/**
	 * Shiro身份验证 信息缓存
	 */
	SHIRO_AUTHENTICATION_CACHE("authentication-cache"),
	/**
	 * Shiro授权信息缓存
	 */
	SHIRO_AUTHORIZATION_CACHE("authorization-cache"),
	/**
	 * Shiro密码错误次数缓存
	 */
	SHIRO_PASSWORD_RETRRY_CACHE("password-retry-cache"),
	/**
	 * Shiro踢出在线用户缓存对象
	 */
	SHIRO_KICKOUT_SESSION_CONTROL_CACHE("kickout-session-control-cache"),
	
	
	SHIRO_AUTHORIZED_URL("login-authorized-url"),
	
	SHIRO_UNAUTHORIZED_URL("login-unauthorized-url"),
	
	LOGIN_TYPE_KEY("login-unauthorized-url"),
	SESSION_USER_KEY("login-unauthorized-url"),
	
	/**
	 */
	URL_EXCLUDE_PATTERN("url-exclude-pattern"),
	
	/**
	 */
	GZIP_COMPRESSION_DISABLED("gzip-compression-disabled"),

	/**
	 * true | false, true will return localhost/127.0.0.1 for hostname/hostaddress, false will attempt dns lookup for hostname (default: false).
	 */
	DNS_LOOKUPS_DISABLED("dns-lookups-disabled");

	private final String code;

	private Parameter(String code) {
		this.code = code;
	}

	/**
	 * @return code de l'enum tel qu'il doit être paramétré
	 */
	public String getCode() {
		return code;
	}

	static Parameter valueOfIgnoreCase(String parameter) {
		return valueOf(parameter.toUpperCase(Locale.ENGLISH).trim());
	}
}
