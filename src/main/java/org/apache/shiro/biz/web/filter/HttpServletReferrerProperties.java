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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.util.StringUtils;

/**
 * referer 安全 配置
 * @author ： <a href="https://github.com/vindell">vindell</a>
 */
public class HttpServletReferrerProperties {

	/**
	 * Specifies the name of the Header on where to find the referer (i.e. Referer).
	 */
	private String refererHeaderName = "Referer";
	/**
	 * Allowed access referrer of the application
	 */
	protected Set<String> allowedReferers = Collections.emptySet();
	/**
	 * Allowed access URI for each referrer
	 */
	private Map<String /* URI Pattern */, String /* Referer */> allowedAccessPatternMap = new LinkedHashMap<String, String>();

	public String getRefererHeaderName() {
		return refererHeaderName;
	}

	public void setRefererHeaderName(String refererHeaderName) {
		this.refererHeaderName = refererHeaderName;
	}

	public Set<String> getAllowedReferers() {
		return allowedReferers;
	}
	/**
     * Sets the allowed Referer
     * @param allowedReferers A comma-delimited list of Referers
     */
    public void setAllowedReferers(String allowedReferers) {
    	this.allowedReferers = StringUtils.commaDelimitedListToSet(allowedReferers);
    }

	public void setAllowedReferers(Set<String> allowedReferers) {
		this.allowedReferers = allowedReferers;
	}

	public Map<String, String> getAllowedAccessPatternMap() {
		return allowedAccessPatternMap;
	}

	public void setAllowedAccessPatternMap(Map<String, String> allowedAccessPatternMap) {
		this.allowedAccessPatternMap = allowedAccessPatternMap;
	}

}
