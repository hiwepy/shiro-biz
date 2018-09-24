package org.apache.shiro.biz.web.filter;

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>Request Method Filter, 对跨域提供支持</p>
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletRequestMethodFilter extends AccessControlFilter {

	private static final Logger LOG = LoggerFactory.getLogger(HttpServletRequestMethodFilter.class);
	public static final String DEFAULT_ACCESS_CONTROL_ALLOW_METHODS = "PUT,POST,GET,DELETE,OPTIONS";

	/**
	 * 应许访问的HTTP方法
	 */
	private String[] allowedHTTPMethods;

	public String[] getAllowedHTTPMethods() {
		return allowedHTTPMethods;
	}

	public void setAllowedHTTPMethods(String[] allowedHTTPMethods) {
		this.allowedHTTPMethods = allowedHTTPMethods;
	}
	
	/** 对跨域提供支持 */
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		
		// 如果没有配置任何方法，直接返回FALSE
		if(allowedHTTPMethods == null || allowedHTTPMethods.length ==0){
			return false;
		}
		
		if(LOG.isDebugEnabled()){
			LOG.debug("HttpServletRequestMethodFilter has config allowed http method:{}.",org.apache.commons.lang3.StringUtils.join(allowedHTTPMethods, ","));
		}
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		//请求使用的方法
		String method = httpRequest.getMethod();
		boolean isAllowed = false;
		//需要过滤HTTP METHOD
		for (String httpMethod : allowedHTTPMethods) {
			if(httpMethod != null && httpMethod.equalsIgnoreCase(method)){
				isAllowed = true;
			}
		}
		if(LOG.isDebugEnabled() && !isAllowed){
			LOG.debug("Request Method:{} is Not Allowed!.Request will be returned with a 403 response!",method);
		}
		return isAllowed;
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		try {
			String mString = String.format("Request Denied! Request Method {%s} is Not Allowed.", httpRequest.getMethod());
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, mString);
		} catch (IOException e) {
			if(LOG.isErrorEnabled()){
				LOG.error("Send Response Error:{}.",e.getCause());
			}
			e.printStackTrace();
		}
		return true;
	}
	
}
