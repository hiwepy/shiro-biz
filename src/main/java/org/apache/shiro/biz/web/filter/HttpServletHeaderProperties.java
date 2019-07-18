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

/**
 * 常用的Http Header 配置
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletHeaderProperties {
	
	public static final String DEFAULT_ACCESS_CONTROL_ALLOW_METHODS = "PUT,POST,GET,DELETE,OPTIONS";
	public static final String DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS = "Accept, Content-Type, Credential, Authorization, Origin, X-Authorization, X-Requested-With,  X-XSRF-TOKEN";
	public static final String DEFAULT_X_FRAME_OPTIONS = "SAMEORIGIN";
	public static final String DEFAULT_X_CONTENT_TYPE_OPTIONS = "nosniff";
	
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
	 */
	private boolean AccessControlAllowCredentials = false;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
	 */
	private String AccessControlAllowHeaders = DEFAULT_ACCESS_CONTROL_ALLOW_HEADERS;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
	 */
	private String AccessControlAllowMethods = DEFAULT_ACCESS_CONTROL_ALLOW_METHODS;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
	 */
	private String AccessControlAllowOrigin = "*";
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
	 */
	private String AccessControlExposeHeaders = "Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma";
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
	 */
	private String AccessControlMaxAge;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
	 */
	private String CacheControl;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
	 */
	private String ContentSecurityPolicy;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
	 */
	private String ContentSecurityPolicyReportOnly;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy
	 */
	private String FeaturePolicy;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
	 */
	private String ReferrerPolicy = "origin";
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
	 */
	private String StrictTransportSecurity;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Timing-Allow-Origin
	 */
	private String TimingAllowOrigin;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
	 */
	private String XContentTypeOptions = DEFAULT_X_CONTENT_TYPE_OPTIONS;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control
	 */
	private String XDnsPrefetchControl = "off";
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
	 */
	private String XFrameOptions = DEFAULT_X_FRAME_OPTIONS;
	/**
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
	 */
	private String XXssProtection = "1; mode=block";

	public boolean isAccessControlAllowCredentials() {
		return AccessControlAllowCredentials;
	}

	public void setAccessControlAllowCredentials(boolean accessControlAllowCredentials) {
		AccessControlAllowCredentials = accessControlAllowCredentials;
	}

	public String getAccessControlAllowHeaders() {
		return AccessControlAllowHeaders;
	}

	public void setAccessControlAllowHeaders(String accessControlAllowHeaders) {
		AccessControlAllowHeaders = accessControlAllowHeaders;
	}

	public String getAccessControlAllowMethods() {
		return AccessControlAllowMethods;
	}

	public void setAccessControlAllowMethods(String accessControlAllowMethods) {
		AccessControlAllowMethods = accessControlAllowMethods;
	}

	public String getAccessControlAllowOrigin() {
		return AccessControlAllowOrigin;
	}

	public void setAccessControlAllowOrigin(String accessControlAllowOrigin) {
		AccessControlAllowOrigin = accessControlAllowOrigin;
	}

	public String getAccessControlExposeHeaders() {
		return AccessControlExposeHeaders;
	}

	public void setAccessControlExposeHeaders(String accessControlExposeHeaders) {
		AccessControlExposeHeaders = accessControlExposeHeaders;
	}

	public String getAccessControlMaxAge() {
		return AccessControlMaxAge;
	}

	public void setAccessControlMaxAge(String accessControlMaxAge) {
		AccessControlMaxAge = accessControlMaxAge;
	}

	public String getCacheControl() {
		return CacheControl;
	}

	public void setCacheControl(String cacheControl) {
		CacheControl = cacheControl;
	}

	public String getContentSecurityPolicy() {
		return ContentSecurityPolicy;
	}

	public void setContentSecurityPolicy(String contentSecurityPolicy) {
		ContentSecurityPolicy = contentSecurityPolicy;
	}

	public String getContentSecurityPolicyReportOnly() {
		return ContentSecurityPolicyReportOnly;
	}

	public void setContentSecurityPolicyReportOnly(String contentSecurityPolicyReportOnly) {
		ContentSecurityPolicyReportOnly = contentSecurityPolicyReportOnly;
	}

	public String getFeaturePolicy() {
		return FeaturePolicy;
	}

	public void setFeaturePolicy(String featurePolicy) {
		FeaturePolicy = featurePolicy;
	}

	public String getReferrerPolicy() {
		return ReferrerPolicy;
	}

	public void setReferrerPolicy(String referrerPolicy) {
		ReferrerPolicy = referrerPolicy;
	}

	public String getStrictTransportSecurity() {
		return StrictTransportSecurity;
	}

	public void setStrictTransportSecurity(String strictTransportSecurity) {
		StrictTransportSecurity = strictTransportSecurity;
	}

	public String getTimingAllowOrigin() {
		return TimingAllowOrigin;
	}

	public void setTimingAllowOrigin(String timingAllowOrigin) {
		TimingAllowOrigin = timingAllowOrigin;
	}

	public String getXContentTypeOptions() {
		return XContentTypeOptions;
	}

	public void setXContentTypeOptions(String xContentTypeOptions) {
		XContentTypeOptions = xContentTypeOptions;
	}

	public String getXDnsPrefetchControl() {
		return XDnsPrefetchControl;
	}

	public void setXDnsPrefetchControl(String xDnsPrefetchControl) {
		XDnsPrefetchControl = xDnsPrefetchControl;
	}

	public String getXFrameOptions() {
		return XFrameOptions;
	}

	public void setXFrameOptions(String xFrameOptions) {
		XFrameOptions = xFrameOptions;
	}

	public String getXXssProtection() {
		return XXssProtection;
	}

	public void setXXssProtection(String xXssProtection) {
		XXssProtection = xXssProtection;
	}

}
