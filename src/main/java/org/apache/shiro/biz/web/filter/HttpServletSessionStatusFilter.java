package org.apache.shiro.biz.web.filter;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.Constants;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.SimpleOnlineSession;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * 在线状态会话过滤器
 * @author <a href="https://github.com/vindell">vindell</a>
 * http://jinnianshilongnian.iteye.com/blog/2047643
 */
public class HttpServletSessionStatusFilter extends AccessControlFilter {

	private SessionManager sessionManager;

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);
        if (subject == null || subject.getSession(false) == null) {
            return true;
        }
        
        Session session = getSessionManager().getSession(new DefaultSessionKey(subject.getSession().getId()));
        if (session != null && session instanceof SimpleOnlineSession) {
        	SimpleOnlineSession onlineSession = (SimpleOnlineSession) session;
            request.setAttribute(Constants.ONLINE_SESSION, onlineSession);
            if (onlineSession.getStatus() == SimpleOnlineSession.OnlineStatus.force_logout) {
                return false;
            }
        }
        return session.getAttribute(Constants.SESSION_FORCE_LOGOUT_KEY) == null;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    	try {
			// Forced Logout
			getSubject(request, response).logout();
		} catch (Exception e) {
			/* ignore exception */
		}
    	String mString = "Request Denied! Session is Force Logout.";
    	if (WebUtils.isAjaxRequest(request)) {
    		
    		WebUtils.toHttp(response).setStatus(HttpStatus.SC_UNAUTHORIZED);
    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(mString));
    		
		} else {
			if (StringUtils.hasText(getLoginUrl())) {
				Map<String, String> parameters = new HashMap<String, String>();
			    parameters.put("forceLogout", "1");
				WebUtils.issueRedirect(request, response, getLoginUrl(), parameters);
			} else {
				WebUtils.toHttp(response).sendError(HttpStatus.SC_UNAUTHORIZED, mString);
			}
		}
		// The request has been processed, no longer enter the next filter
		return false;
    }

	public SessionManager getSessionManager() {
		return sessionManager;
	}

	public void setSessionManager(SessionManager sessionManager) {
		this.sessionManager = sessionManager;
	}
    
}