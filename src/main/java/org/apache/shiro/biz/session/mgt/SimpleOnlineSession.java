/*
 * Copyright (c) 2018 (https://github.com/vindell).
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
package org.apache.shiro.biz.session.mgt;

import org.apache.shiro.session.mgt.SimpleSession;

@SuppressWarnings("serial")
public class SimpleOnlineSession extends SimpleSession {
	
	protected String userAgent; 	//用户浏览器类型
	protected OnlineStatus status = OnlineStatus.on_line; //在线状态
	protected String systemHost; 	//用户登录时系统IP
    
    public static enum OnlineStatus {
    	
        on_line("在线"), 
        hidden("隐身"), 
        force_logout("强制退出");
    	
        private final String info;
        private OnlineStatus(String info) {
            this.info = info;
        }
        public String getInfo() {
            return info;
        }
    }
    
    public SimpleOnlineSession() {
    	super();
    }

    public SimpleOnlineSession(String host) {
       super(host);
    }
    
	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public OnlineStatus getStatus() {
		return status;
	}

	public void setStatus(OnlineStatus status) {
		this.status = status;
	}

	public String getSystemHost() {
		return systemHost;
	}

	public void setSystemHost(String systemHost) {
		this.systemHost = systemHost;
	}
    
}