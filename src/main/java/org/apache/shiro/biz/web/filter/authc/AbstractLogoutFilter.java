package org.apache.shiro.biz.web.filter.authc;

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;

public class AbstractLogoutFilter extends LogoutFilter {

	/**
	 * 注销回调监听
	 */
	protected List<LogoutListener> logoutListeners;
	/**
	 * 是否单点登录
	 */
	protected boolean casLogin = false;
	
	
	public String getCasRedirectUrl(ServletRequest request, ServletResponse response) {
		return super.getRedirectUrl();
	}
	
	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response)
			throws Exception {
		
		Subject subject = getSubject(request, response);
		
		//调用事件监听器
		if(getLogoutListeners() != null && getLogoutListeners().size() > 0){
			for (LogoutListener logoutListener : getLogoutListeners()) {
				logoutListener.beforeLogout(subject, request, response);
			}
		}
		
		// 如果是单点登录，需要重新构造登出的重定向地址
		if(this.isCasLogin()){
			// 重定向到单点登出地址
			issueRedirect(request, response, getCasRedirectUrl(request, response));
			return false;
		}
		
		Exception ex = null;
		boolean result = false;
		try {
			// do real thing
			result = super.preHandle(request, response);
		} catch (Exception e) {
			ex = e;
		}
		
		//调用事件监听器
		if(getLogoutListeners() != null && getLogoutListeners().size() > 0){
			for (LogoutListener logoutListener : getLogoutListeners()) {
				if(ex != null){
					logoutListener.onLogoutFail(subject, ex);
				}else{
					logoutListener.onLogoutSuccess(request, response);
				}
			}
		}
		
		if(ex != null){
			throw ex;
		}
		
		return result;
	}
	
	public List<LogoutListener> getLogoutListeners() {
		return logoutListeners;
	}

	public void setLogoutListeners(List<LogoutListener> logoutListeners) {
		this.logoutListeners = logoutListeners;
	}

	public boolean isCasLogin() {
		return casLogin;
	}

	public void setCasLogin(boolean casLogin) {
		this.casLogin = casLogin;
	}
	
	
}
