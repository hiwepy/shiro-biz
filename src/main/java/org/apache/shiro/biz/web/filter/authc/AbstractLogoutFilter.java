package org.apache.shiro.biz.web.filter.authc;

import java.util.List;
import java.util.Locale;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.ShiroBizMessageSource;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.authc.AuthcResponseCode;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.filter.authc.listener.LogoutListener;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * 扩展Shiro登出逻辑，增加监听回调接口
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public abstract class AbstractLogoutFilter extends LogoutFilter {
	
	private static final Logger LOG = LoggerFactory.getLogger(AbstractLogoutFilter.class);
	protected MessageSourceAccessor messages =ShiroBizMessageSource.getAccessor();
	/**
	 * 注销回调监听
	 */
	protected List<LogoutListener> logoutListeners;
	/** If Session Stateless */
	private boolean sessionStateless = false;
	
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
		
        // Check if POST only logout is enabled
        if (isPostOnlyLogout()) {
            // check if the current request's method is a POST, if not redirect
            if (!WebUtils.toHttp(request).getMethod().toUpperCase(Locale.ENGLISH).equals("POST")) {
               return onLogoutRequestNotAPost(request, response);
            }
        }
        
        String redirectUrl = getRedirectUrl(request, response, subject);
        //try/catch added for SHIRO-298:
        try {
            subject.logout();
        } catch (SessionException ise) {
        	LOG.debug("Encountered session exception during logout.  This can generally safely be ignored.", ise);
        }
        
    	if( isSessionStateless() || WebUtils.isAjaxRequest(request)) {
			
			// Response success status information
    		
    		WebUtils.toHttp(response).setStatus(HttpStatus.SC_OK);
    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
    		
    		// Response logout status information
    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.logout(
    				messages.getMessage(AuthcResponseCode.SC_AUTHC_LOGOUT.getMsgKey())));
			
			return false;
		}
        
        issueRedirect(request, response, redirectUrl);
        return false;

	}
	
	public List<LogoutListener> getLogoutListeners() {
		return logoutListeners;
	}

	public void setLogoutListeners(List<LogoutListener> logoutListeners) {
		this.logoutListeners = logoutListeners;
	}

	public boolean isSessionStateless() {
		return sessionStateless;
	}

	public void setSessionStateless(boolean sessionStateless) {
		this.sessionStateless = sessionStateless;
	}
	
}
