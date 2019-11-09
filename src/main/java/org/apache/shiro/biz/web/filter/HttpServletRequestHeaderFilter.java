/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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

import java.util.Optional;

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

import com.google.common.net.HttpHeaders;

/**
 * 
 * Http Header 规则配置过滤器 
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * <p>https://blog.csdn.net/guodengh/article/details/73187908 </p>
 * <p>https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Access_control_CORS </p>
 * <p>https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Access-Control-Allow-Headers </p>
 */
public class HttpServletRequestHeaderFilter extends AccessControlFilter {
	
	private static final Logger LOG = LoggerFactory.getLogger(HttpServletRequestHeaderFilter.class);
	public static final String FEATURE_POLICY_KEY = "Feature-Policy";
	
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
		Optional.ofNullable(properties.isAccessControlAllowCredentials()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, Boolean.toString(properties.isAccessControlAllowCredentials()));
		});
		Optional.ofNullable(properties.getAccessControlAllowHeaders()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, properties.getAccessControlAllowHeaders());
		});
		Optional.ofNullable(properties.getAccessControlAllowMethods()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, properties.getAccessControlAllowMethods());
		});
		Optional.ofNullable(properties.getAccessControlAllowOrigin()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, properties.getAccessControlAllowOrigin());
		});
		Optional.ofNullable(properties.getAccessControlExposeHeaders()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, properties.getAccessControlExposeHeaders());
		});
		Optional.ofNullable(properties.getAccessControlMaxAge()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.ACCESS_CONTROL_MAX_AGE, properties.getAccessControlMaxAge());
		});
		Optional.ofNullable(properties.getCacheControl()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.CACHE_CONTROL, properties.getCacheControl());
		});
		Optional.ofNullable(properties.getContentSecurityPolicy()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.X_CONTENT_SECURITY_POLICY, properties.getContentSecurityPolicy());
		});
		Optional.ofNullable(properties.getContentSecurityPolicyReportOnly()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.X_CONTENT_SECURITY_POLICY_REPORT_ONLY, properties.getContentSecurityPolicyReportOnly());
		});
		Optional.ofNullable(properties.getReferrerPolicy()).ifPresent(value -> {
			this.setHeader(httpResponse, FEATURE_POLICY_KEY, properties.getReferrerPolicy());
		});
		Optional.ofNullable(properties.getFeaturePolicy()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.REFERRER_POLICY, properties.getFeaturePolicy());
		});
		Optional.ofNullable(properties.getStrictTransportSecurity()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.STRICT_TRANSPORT_SECURITY, properties.getStrictTransportSecurity());
		});
		Optional.ofNullable(properties.getTimingAllowOrigin()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.TIMING_ALLOW_ORIGIN, properties.getTimingAllowOrigin());
		});
		//防止在IE9、chrome和safari中的MIME类型混淆攻击
		Optional.ofNullable(properties.getTimingAllowOrigin()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.X_CONTENT_TYPE_OPTIONS, properties.getXContentTypeOptions());
		});
		Optional.ofNullable(properties.getXDnsPrefetchControl()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.X_DNS_PREFETCH_CONTROL, properties.getXDnsPrefetchControl());
		});
		//iframe策略
		Optional.ofNullable(properties.getXFrameOptions()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.X_FRAME_OPTIONS, properties.getXFrameOptions());
		});
		//X-XSS-Protection：主要是用来防止浏览器中的反射性xss，IE，chrome和safari（webkit）支持这个header,有以下两种方式：
		//1; mode=block – 开启xss防护并通知浏览器阻止而不是过滤用户注入的脚本；
		//1; report=http://site.com/report – 这个只有chrome和webkit内核的浏览器支持，这种模式告诉浏览器当
		//发现疑似xss攻击的时候就将这部分数据post到指定地址。
		Optional.ofNullable(properties.getXXssProtection()).ifPresent(value -> {
			this.setHeader(httpResponse, HttpHeaders.X_XSS_PROTECTION, properties.getXXssProtection());
		});
		
		// 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
		if (httpRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
			httpResponse.setStatus(HttpServletResponse.SC_OK);
			return false;
		}
		
		return true;
	}
	
	protected void setHeader(HttpServletResponse response, String key, String value) {
		if(StringUtils.hasText(value)) {
			boolean match = response.getHeaderNames().stream().anyMatch(item -> StringUtils.equalsIgnoreCase(item, key));
			if(!match) {
				response.setHeader(key, value);
				if(LOG.isDebugEnabled()){
					LOG.debug("Filter:{} Set HTTP HEADER: {}:{}.", getName(), key, value);
				}
			}
		}
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
		WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
	}
	
	
}
