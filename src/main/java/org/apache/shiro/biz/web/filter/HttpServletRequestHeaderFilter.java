/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.biz.web.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.biz.utils.StringUtils;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * 
 * Http Header 规则配置过滤器 
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * <p>https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Access_control_CORS </p>
 * <p>https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Access-Control-Allow-Headers </p>
 */
public class HttpServletRequestHeaderFilter extends AccessControlFilter {
	
	private static final Logger LOG = LoggerFactory.getLogger(HttpServletRequestHeaderFilter.class);
	public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS_KEY = "Access-Control-Allow-Credentials";
	public static final String ACCESS_CONTROL_ALLOW_HEADERS_KEY = "Access-Control-Allow-Headers";
	public static final String ACCESS_CONTROL_ALLOW_METHODS_KEY = "Access-Control-Allow-Methods";
	public static final String ACCESS_CONTROL_ALLOW_ORIGIN_KEY = "Access-Control-Allow-Origin";
	public static final String ACCESS_CONTROL_EXPOSE_HEADERS_KEY = "Access-Control-Expose-Headers";
	public static final String ACCESS_CONTROL_MAX_AGE_KEY = "Access-Control-Max-Age";
	public static final String CACHE_CONTROL_KEY = "Cache-Control";
	public static final String CONTENT_SECURITY_POLICY_KEY = "Content-Security-Policy";
	public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_KEY = "Content-Security-Policy-Report-Only";
	public static final String FEATURE_POLICY_KEY = "Feature-Policy";
	public static final String REFERRER_POLICY_KEY = "Referrer-Policy";
	public static final String STRICT_TRANSPORT_SECURITY_KEY = "Strict-Transport-Security";
	public static final String TIMING_ALLOW_ORIGIN_KEY = "Timing-Allow-Origin";
	public static final String X_CONTENT_TYPE_OPTIONS_KEY = "X-Content-Type-Options";
	public static final String X_DNS_PREFETCH_CONTROL_KEY = "X-DNS-Prefetch-Control";
	public static final String X_FRAME_OPTIONS_KEY = "X-Frame-Options";
	public static final String X_XSS_PROTECTION_KEY = "X-XSS-Protection";
	
	private final HttpServletHeaderProperties properties;
	
	public HttpServletRequestHeaderFilter(HttpServletHeaderProperties properties) {
		this.properties = properties;
	}
	
	@Override
	protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
			throws Exception {
		
		HttpServletRequest httpRequest = WebUtils.toHttp(request);
		HttpServletResponse httpResponse = WebUtils.toHttp(response);
		
		// 服务器端 Access-Control-Allow-Credentials = true时，参数Access-Control-Allow-Origin 的值不能为 '*' 
		this.setHeader(httpResponse, ACCESS_CONTROL_ALLOW_CREDENTIALS_KEY, Boolean.toString(properties.isAccessControlAllowCredentials()));
		this.setHeader(httpResponse, ACCESS_CONTROL_ALLOW_HEADERS_KEY, properties.getAccessControlAllowHeaders());
		this.setHeader(httpResponse, ACCESS_CONTROL_ALLOW_METHODS_KEY, properties.getAccessControlAllowMethods());
		this.setHeader(httpResponse, ACCESS_CONTROL_ALLOW_ORIGIN_KEY, properties.getAccessControlAllowOrigin());
		this.setHeader(httpResponse, ACCESS_CONTROL_EXPOSE_HEADERS_KEY, properties.getAccessControlExposeHeaders());
		this.setHeader(httpResponse, ACCESS_CONTROL_MAX_AGE_KEY, properties.getAccessControlMaxAge());
		this.setHeader(httpResponse, CACHE_CONTROL_KEY, properties.getCacheControl());
		this.setHeader(httpResponse, CONTENT_SECURITY_POLICY_KEY, properties.getContentSecurityPolicy());
		this.setHeader(httpResponse, CONTENT_SECURITY_POLICY_REPORT_ONLY_KEY, properties.getContentSecurityPolicyReportOnly());
		this.setHeader(httpResponse, FEATURE_POLICY_KEY, properties.getReferrerPolicy());
		this.setHeader(httpResponse, REFERRER_POLICY_KEY, properties.getFeaturePolicy());
		this.setHeader(httpResponse, STRICT_TRANSPORT_SECURITY_KEY, properties.getStrictTransportSecurity());
		this.setHeader(httpResponse, TIMING_ALLOW_ORIGIN_KEY, properties.getTimingAllowOrigin());
		//防止在IE9、chrome和safari中的MIME类型混淆攻击
		this.setHeader(httpResponse, X_CONTENT_TYPE_OPTIONS_KEY, properties.getXContentTypeOptions());
		this.setHeader(httpResponse, X_DNS_PREFETCH_CONTROL_KEY, properties.getXDnsPrefetchControl());
		//iframe策略
		this.setHeader(httpResponse, X_FRAME_OPTIONS_KEY, properties.getXFrameOptions());
		//X-XSS-Protection：主要是用来防止浏览器中的反射性xss，IE，chrome和safari（webkit）支持这个header,有以下两种方式：
		//1; mode=block – 开启xss防护并通知浏览器阻止而不是过滤用户注入的脚本；
		//1; report=http://site.com/report – 这个只有chrome和webkit内核的浏览器支持，这种模式告诉浏览器当
		//发现疑似xss攻击的时候就将这部分数据post到指定地址。
		this.setHeader(httpResponse, X_XSS_PROTECTION_KEY, properties.getXXssProtection());
		
		// 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			httpResponse.setStatus(HttpServletResponse.SC_OK);
			return false;
		}
		return true;
	}
	
	protected void setHeader(HttpServletResponse response, String key, String value) {
		if(StringUtils.hasText(value)) {
			if(LOG.isDebugEnabled()){
				LOG.debug("Filter:{} Set HTTP HEADER: {}:{}.", getName(), key, value);
			}
			response.setHeader(key, value);
		}
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		return true;
	}
	
}
