package org.apache.shiro.biz.web.filter.authc;

import java.util.List;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.web.filter.authc.listener.LogoutListener;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;

/**
 * 扩展Shiro登出逻辑，增加监听回调接口
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstractLogoutFilter extends LogoutFilter {

	/**
	 * 注销回调监听
	 */
	protected List<LogoutListener> logoutListeners;
	
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
		
		Exception ex = null;
		boolean result = false;
		try {
			// do real thing
			result = this.logout(request, response, subject);
		} catch (Exception e) {
			ex = e;
		}
		
		//调用事件监听器
		if(getLogoutListeners() != null && getLogoutListeners().size() > 0){
			for (LogoutListener logoutListener : getLogoutListeners()) {
				if(ex != null){
					logoutListener.onFailure(subject, ex);
				}else{
					logoutListener.onSuccess(subject, request, response);
				}
			}
		}
		
		if(ex != null){
			throw ex;
		}
		
		return result;
	}
	
	protected boolean logout(ServletRequest request, ServletResponse response, Subject subject) throws Exception{
		// do real thing
		return super.preHandle(request, response);
	}
	
	public List<LogoutListener> getLogoutListeners() {
		return logoutListeners;
	}

	public void setLogoutListeners(List<LogoutListener> logoutListeners) {
		this.logoutListeners = logoutListeners;
	}
	
}
