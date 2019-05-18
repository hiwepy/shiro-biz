package org.apache.shiro.biz.web.filter;

import java.io.IOException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.biz.authc.AuthcResponse;
import org.apache.shiro.biz.utils.WebUtils;
import org.apache.shiro.biz.web.servlet.http.HttpStatus;
import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.springframework.http.MediaType;

import com.alibaba.fastjson.JSONObject;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.RateLimiter;

/**
 * 基于Guava提供的限流工具类RateLimiter实现的访问请求限流过滤器
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletRequestLimitWithPathFilter extends AccessControlFilter {
	
	/** 路径规则匹配工具 */
	protected AntPathMatcher pathMatcher = new AntPathMatcher();
	/** 不同的请求路径限速  */
	protected Map<String /* Pattern */, String /* Permits Per Second */> limiterDefinitionMap = new LinkedHashMap<String, String>();
	/** 根据请求地址按规则分不同的令牌桶, 每天自动清理缓存 */
	protected LoadingCache<String, RateLimiter> limiterCaches;
	/** 是否等待请求完成 */
	protected boolean requestWaitCompleted = false;
	/** the maximum number of entries the cache may contain. */
	protected long maximumSize = 1000;
	
	@Override
	protected void onFilterConfigSet() throws Exception {
		super.onFilterConfigSet();
		this.limiterCaches = CacheBuilder.newBuilder()
				.maximumSize(maximumSize)
				.expireAfterWrite(1, TimeUnit.DAYS)
				.build(new CacheLoader<String, RateLimiter>() {
					@Override
					public RateLimiter load(String pattern) throws Exception {
						return RateLimiter.create(Double.parseDouble(getLimiterDefinitionMap().get(pattern)));
					}
				});
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
		
		if (MapUtils.isNotEmpty(getLimiterDefinitionMap())) {
			
			String requestURI = WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
			Iterator<Entry<String, String>> ite = getLimiterDefinitionMap().entrySet().iterator();
			
			while(ite.hasNext()) {
				
				Entry<String, String> entry = ite.next();
				if (getPathMatcher().match(entry.getKey(), requestURI)) {
					try {
						RateLimiter ret = limiterCaches.get(entry.getKey());
						if(isRequestWaitCompleted()) { 
							ret.acquire();
							super.doFilterInternal(request, response, chain);
						} else if(ret.tryAcquire()){
							super.doFilterInternal(request, response, chain);
						} else {
							String mString = String.format("Request Forbidden! Requests per second exceeds %s limit.", entry.getValue());
							if (WebUtils.isAjaxRequest(request)) {
					    		WebUtils.toHttp(response).setStatus(HttpStatus.SC_FORBIDDEN);
					    		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
					    		JSONObject.writeJSONString(response.getWriter(), AuthcResponse.error(mString));
							} else {
								WebUtils.toHttp(response).sendError(HttpStatus.SC_FORBIDDEN, mString);
							}
						}
					} catch (ExecutionException e) {
					}
				}
			}
		} else {
			super.doFilterInternal(request, response, chain);
		}
	}

	public Map<String, String> getLimiterDefinitionMap() {
		return limiterDefinitionMap;
	}

	public void setLimiterDefinitionMap(Map<String, String> limiterDefinitionMap) {
		this.limiterDefinitionMap = limiterDefinitionMap;
	}

	public AntPathMatcher getPathMatcher() {
		return pathMatcher;
	}

	public void setPathMatcher(AntPathMatcher pathMatcher) {
		this.pathMatcher = pathMatcher;
	}

	public boolean isRequestWaitCompleted() {
		return requestWaitCompleted;
	}

	public void setRequestWaitCompleted(boolean requestWaitCompleted) {
		this.requestWaitCompleted = requestWaitCompleted;
	}

	public long getMaximumSize() {
		return maximumSize;
	}

	public void setMaximumSize(long maximumSize) {
		this.maximumSize = maximumSize;
	}
	
}
