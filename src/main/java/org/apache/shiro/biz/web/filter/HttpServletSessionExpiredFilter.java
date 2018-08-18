package org.apache.shiro.biz.web.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;

/**
 * 会话超时过滤器
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletSessionExpiredFilter extends AccessControlFilter {

	@Override
	public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {

		Subject subject = SecurityUtils.getSubject();
		if (subject == null || !subject.isAuthenticated()) {
			if (WebUtils.isAjaxRequest(request)) {
				// 响应成功状态信息
		        WebUtils.writeJSONString(response, HttpStatus.SC_SESSION_TIMEOUT, "Session Timeout.");
				return false;
			}
		}
		return true;
	}

	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return false;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return false;
	}

}