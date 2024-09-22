package org.apache.shiro.biz.web.filter;

import com.alibaba.fastjson2.JSON;
import org.apache.commons.collections.MapUtils;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils2;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;


public class HttpServletRequestReferrerFilter extends AccessControlFilter {

	protected Logger LOG = LoggerFactory.getLogger(getClass());
	protected PathMatcher matcher = new AntPathMatcher();
	private final HttpServletReferrerProperties properties;
	
	public HttpServletRequestReferrerFilter(HttpServletReferrerProperties properties) {
		this.properties = properties;
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		//请求的request对象
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		//获取请求访问来源；referer为客户端带来的请求头 
		String referer = httpRequest.getHeader(properties.getRefererHeaderName());
		/*  request.getHeader("Referer")获取来访者地址。
			只有通过链接访问当前页的时候，才能获取上一页的地址；否则request.getHeader("Referer")的值为Null，
			通过window.open打开当前页或者直接输入地址，也为Null。
		*/
		//来源为空
		if(StringUtils.isEmpty(referer)){
			return false;
		}
		
		if ( MapUtils.isNotEmpty(properties.getAllowedRefererPatterns())) {
			Iterator<Entry<String, String>> ite = properties.getAllowedRefererPatterns().entrySet().iterator();
			while (ite.hasNext()) {
				Entry<String, String> entry = ite.next();
				if(!matcher.match(entry.getKey(), httpRequest.getRequestURI())) {
					continue;
				}
				Set<String> allowedReferers = StringUtils.commaDelimitedListToSet(entry.getValue());
		    	for (String allowedReferer : allowedReferers) {
		    		if(matcher.match(allowedReferer, referer)) {
						return true;
					}
				}
			}
		}
		
		if(LOG.isDebugEnabled()){
			LOG.debug("Not Allowed Access Referrer : {}.", referer );
		}
		return false;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		String mString = String.format("Request Denied! Request Referer {%s} is Not Allowed.", WebUtils.toHttp(request).getHeader(properties.getRefererHeaderName()));
		//判断是否ajax请求
		if (WebUtils2.isAjaxResponse(request)) {
			WebUtils.toHttp(response).setStatus(HttpStatus.SC_FORBIDDEN);
    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
    		JSON.writeTo(response.getOutputStream(), AuthcResponse.error(mString));
		} else {
			WebUtils.toHttp(response).sendError(HttpStatus.SC_FORBIDDEN, mString);
		}
		// The request has been processed, no longer enter the next filter
		return false;
	}
	
}
