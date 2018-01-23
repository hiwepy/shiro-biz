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
/**
 * 
 * @className	： LoginType
 * @description	：登录类型枚举；1：系统正常登录；2：外部单点登录；3：外部票据登录（通过握手秘钥等参数认证登录）
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午6:10:15
 * @version 	V1.0
 */
public enum LoginType {

	/**
	 * 1：系统正常登录
	 */
	DEFAULE("default","系统正常登录"),
	/**
	 * 2：外部单点登录
	 */
	SSO("sso","外部单点登录"),
	/**
	 * 3：外部票据登录（通过握手秘钥等参数认证登录）
	 */
	TICKET("ticket","外部票据登录（通过握手秘钥等参数认证登录）");
	
	protected String key;
	protected String desc;
	
	LoginType(String key,String desc){
		this.key = key;
		this.desc = desc;
	}
	
	@Override
	public String toString() {
		return desc;
	}

	public String getKey() {
		return key;
	}

	public String getDesc() {
		return desc;
	}
	
	public String getRealmName() {
		return key + "Realm";
	}
	
	public boolean equalsTo(String type){
		return this.getKey().equalsIgnoreCase(type);
	}
	
	public boolean equalsTo(LoginType type){
		return this.getKey().equalsIgnoreCase(type.getKey());
	}
	
}
