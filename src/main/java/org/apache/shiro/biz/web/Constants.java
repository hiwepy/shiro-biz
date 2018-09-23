package org.apache.shiro.biz.web;

public class Constants {
	
	public static final String PARAM_DIGEST = "digest";
	public static final String PARAM_USERNAME = "username";
	public static final String SESSION_FORCE_LOGOUT_KEY = "session-force-logout";

	/**
	 * 当前在线会话
	 */
	public static final String ONLINE_SESSION = "online_session";

	/**
	 * 仅清空本地缓存 不情况数据库的
	 */
	public static final String ONLY_CLEAR_CACHE = "online_session_only_clear_cache";

}
