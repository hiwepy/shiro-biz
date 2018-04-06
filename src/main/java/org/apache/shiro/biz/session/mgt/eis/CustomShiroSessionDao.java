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
package org.apache.shiro.biz.session.mgt.eis;

import java.io.Serializable;
import java.util.Collection;

import org.apache.shiro.biz.session.SessionRepository;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.eis.AbstractSessionDAO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
public class CustomShiroSessionDao extends AbstractSessionDAO {
	
	protected static Logger LOG = LoggerFactory.getLogger(CustomShiroSessionDao.class);
	protected SessionRepository shiroSessionRepository;
 
    public SessionRepository getShiroSessionRepository() {
        return shiroSessionRepository;
    }
 
    public void setShiroSessionRepository(SessionRepository shiroSessionRepository) {
        this.shiroSessionRepository = shiroSessionRepository;
    }
    
    /*
     * 如DefaultSessionManager在创建完session后会调用该方法；
     * 如保存到关系数据库/文件系统/NoSQL数据库；即可以实现会话的持久化；
     * 返回会话ID；主要此处返回的ID.equals(session.getId())；
     */
	@Override
	protected Serializable doCreate(Session session) {
		// 创建一个Id并设置给Session
		Serializable sessionId = this.generateSessionId(session);
		this.assignSessionId(session, sessionId);
		getShiroSessionRepository().saveSession(session);
		return sessionId;
	}

	/*
     * 根据会话ID获取会话  
     */
	@Override
	protected Session doReadSession(Serializable sessionId) {
		if(sessionId == null){  
            LOG.error("Session ID is null");  
            return null;  
        }  
		return getShiroSessionRepository().getSession(sessionId);
	}

	/*
     * 删除会话；当会话过期/会话停止（如用户退出时）会调用  
     */
	@Override
	public void delete(Session session) {
		if(session == null || session.getId() == null){  
            LOG.error("Session or Session ID is null");  
            return;  
        }  
		getShiroSessionRepository().deleteSession(session.getId());
		LOG.info("取消 Session {} 的缓存", session.getId());
	}
	
	/*
     * 更新会话；如更新会话最后访问时间/停止会话/设置超时时间/设置移除属性等会调用
     */
	@Override
	public void update(Session session) throws UnknownSessionException {
		getShiroSessionRepository().saveSession(session);
	}

	/*
     * 获取当前所有活跃用户，如果用户量多此方法影响性能
     */
	@Override
	public Collection<Session> getActiveSessions() {
		return getShiroSessionRepository().getAllSessions();
	}
 
   
}
