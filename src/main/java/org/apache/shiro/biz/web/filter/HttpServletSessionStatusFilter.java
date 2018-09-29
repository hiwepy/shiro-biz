package org.apache.shiro.biz.web.filter;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.Constants;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SimpleOnlineSession;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;

/**
 * 在线状态会话过滤器
 * @author <a href="https://github.com/vindell">vindell</a>
 * http://jinnianshilongnian.iteye.com/blog/2047643
 */
public class HttpServletSessionStatusFilter extends AccessControlFilter {

    private SessionDAO sessionDAO;

    public void setSessionDAO(SessionDAO sessionDAO) {
        this.sessionDAO = sessionDAO;
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        Subject subject = getSubject(request, response);
        if (subject == null || subject.getSession(false) == null) {
            return true;
        }
        Session session = sessionDAO.readSession(subject.getSession().getId());
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
			WebUtils.writeJSONString(response, HttpServletResponse.SC_UNAUTHORIZED, mString);
		} else {
			if (StringUtils.hasText(getLoginUrl())) {
				Map<String, String> parameters = new HashMap<String, String>();
			    parameters.put("forceLogout", "1");
				WebUtils.issueRedirect(request, response, getLoginUrl(), parameters);
			} else {
				WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, mString);
			}
		}
		// The request has been processed, no longer enter the next filter
		return false;
    }

}