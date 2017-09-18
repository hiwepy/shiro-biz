/*
 * Copyright (c) 2010-2020, vindell (https://github.com/vindell).
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
package org.apache.shiro.biz.authc.token;

import java.util.Map;

import org.apache.shiro.authc.AuthenticationToken;

public class StatelessToken implements AuthenticationToken {
	
	private String username;
	private Map<String, String[]> params;
	private String clientDigest;

	public StatelessToken(String username, Map<String, String[]> params, String clientDigest) {
		this.username = username;
		this.params = params;
		this.clientDigest = clientDigest;
	}

	// 省略部分代码
	public Object getPrincipal() {
		return username;
	}

	public Object getCredentials() {
		return clientDigest;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Map<String, String[]> getParams() {
		return params;
	}

	public void setParams(Map<String, String[]> params) {
		this.params = params;
	}

	public String getClientDigest() {
		return clientDigest;
	}

	public void setClientDigest(String clientDigest) {
		this.clientDigest = clientDigest;
	}
	
	
	
	
}
