package org.apache.shiro.biz.web.filter;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;

/**
 * 会话超时过滤器
 * @author <a href="https://github.com/vindell">vindell</a>
 * https://blog.csdn.net/ZhangjcGG/article/details/79014030
 */
public class HttpServletSessionExpiredFilter extends AccessControlFilter {
	
	private static final Logger LOG = LoggerFactory.getLogger(HttpServletSessionExpiredFilter.class);
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		Subject subject = getSubject(request, response);
		// Ignore without login
		if(subject == null) {
			return true;
		}
		return subject.isAuthenticated();
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		String mString = "Request Denied! Session is Expired.";
		if (WebUtils.isAjaxRequest(request)) {
			WebUtils.toHttp(response).setHeader("session-status", "timeout");
			WebUtils.toHttp(response).setStatus(HttpStatus.SC_FORBIDDEN);
    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(mString));
			return false;
		} else {
			try {
				WebUtils.toHttp(response).sendError(HttpStatus.SC_FORBIDDEN, mString);
			} catch (IOException e) {
				if(LOG.isErrorEnabled()){
					LOG.error("Send Response Error:{}.",e.getCause());
				}
				throw e;
			}
		}
		// The request has been processed, no longer enter the next filter
		return false;
	}

}