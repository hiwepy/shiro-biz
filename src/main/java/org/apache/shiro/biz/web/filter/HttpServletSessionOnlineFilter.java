package org.apache.shiro.biz.web.filter;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

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
 */
public class HttpServletSessionOnlineFilter extends AccessControlFilter {

	/**
     * 强制退出后重定向的地址
     */
    private String forceLogoutUrl;

    private SessionDAO sessionDAO;

    public String getForceLogoutUrl() {
        return forceLogoutUrl;
    }

    public void setForceLogoutUrl(String forceLogoutUrl) {
        this.forceLogoutUrl = forceLogoutUrl;
    }

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
        return true;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = getSubject(request, response);
        if (subject != null) {
            subject.logout();
        }
        saveRequestAndRedirectToLogin(request, response);
        return true;
    }

    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        WebUtils.issueRedirect(request, response, getForceLogoutUrl());
    }

}