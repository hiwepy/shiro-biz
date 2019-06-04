package org.apache.shiro.biz.web.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;
import com.google.common.util.concurrent.RateLimiter;

/**
 * 基于Guava提供的限流工具类RateLimiter实现的访问请求限流过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletRequestLimitFilter extends AccessControlFilter {
	
	/** 令牌桶限流器 */
	protected RateLimiter rateLimiter;
	/** 是否等待请求完成 */
	protected boolean requestWaitCompleted = false;
	/** rate of the returned {@code RateLimiter}, measured in how many permits become available per second. */
	protected double permitsPerSecond = 500;
	
	@Override
	protected void onFilterConfigSet() throws Exception {
		super.onFilterConfigSet();
		if(this.rateLimiter != null) {
			this.rateLimiter = RateLimiter.create(permitsPerSecond);
		}
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		return true;
	}
	
	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}
	
	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		if(isRequestWaitCompleted()) { 
			this.rateLimiter.acquire();
			super.doFilterInternal(request, response, chain);
		} else if(this.rateLimiter.tryAcquire()){
			super.doFilterInternal(request, response, chain);
		} else {
			String mString = String.format("Request Forbidden! Requests per second exceeds %s limit.", permitsPerSecond);
	    	if (WebUtils.isAjaxResponse(request)) {
	    		
	    		WebUtils.toHttp(response).setStatus(HttpStatus.SC_FORBIDDEN);
	    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
	    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(mString));
	    		
			} else {
				WebUtils.toHttp(response).sendError(HttpStatus.SC_FORBIDDEN, mString);
			}
		}
			
	}

	public RateLimiter getRateLimiter() {
		return rateLimiter;
	}

	public void setRateLimiter(RateLimiter rateLimiter) {
		this.rateLimiter = rateLimiter;
	}

	public boolean isRequestWaitCompleted() {
		return requestWaitCompleted;
	}

	public void setRequestWaitCompleted(boolean requestWaitCompleted) {
		this.requestWaitCompleted = requestWaitCompleted;
	}

	public double getPermitsPerSecond() {
		return permitsPerSecond;
	}

	public void setPermitsPerSecond(double permitsPerSecond) {
		this.permitsPerSecond = permitsPerSecond;
	}
	
}
