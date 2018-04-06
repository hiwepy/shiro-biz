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
package org.apache.shiro.biz.cache.redis.session;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.biz.cache.redis.RedisManager;
import org.apache.shiro.biz.session.SessionRepository;
import org.apache.shiro.biz.utils.SerializeUtils;
import org.apache.shiro.session.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JedisShiroSessionRepository  implements SessionRepository{
	
	protected static Logger LOG = LoggerFactory.getLogger(JedisShiroSessionRepository.class);
	
    /** 
     * shiro-redis的session对象前缀 
     */  
    protected RedisManager redisManager;  
      
    /** 
     * The Redis key prefix for the sessions  
     */
    protected String keyPrefix = "shiro_redis_session:";  
 
    /** 
     * 保存 Session
     */
    @Override
    public void saveSession(Session session) {
        if (session == null || session.getId() == null) {
            System.out.println("session 或者 session ID 为空");
        }
        byte[] key = SerializeUtils.serialize(getRedisSessionKey(session.getId()));
        byte[] value = SerializeUtils.serialize(session);
 
        session.setTimeout(redisManager.getExpire() * 1000);        
        redisManager.set(key, value, redisManager.getExpire());  
        
    }
 
    /**
     * 删除cache中缓存的Session
     */
    @Override
    public void deleteSession(Serializable sessionId) {
        redisManager.del(SerializeUtils.serialize(getRedisSessionKey(sessionId)));
    }
 
    @Override
    public Session getSession(Serializable sessionId) {
        Session session = null;
        byte[] value = redisManager.get(SerializeUtils.serialize(getRedisSessionKey(sessionId)));
        if (null == value){
            return null;
        }
        session = (Session) SerializeUtils.deserialize(value);
        return session;
    }
 
    /**
     * 获取当前所有活跃用户，如果用户量多此方法影响性能
     */
    @Override
    public Collection<Session> getAllSessions() {
    	Set<Session> sessions = new HashSet<Session>();  
        Set<byte[]> keys = redisManager.keys(this.keyPrefix + "*");  
        if(keys != null && keys.size()>0){  
        	//redisManager.mget(keys.toArray(new String[keys.size()]));
            for(byte[] key:keys){  
                Session s = (Session)SerializeUtils.deserialize(redisManager.get(key));  
                sessions.add(s);  
            }  
        }  
        return sessions;
    }
 
    public RedisManager getRedisManager() {
        return redisManager;
    }
 
    public void setRedisManager(RedisManager redisManager) {
        this.redisManager = redisManager;
        /** 
         * 初始化redisManager 
         */  
        this.redisManager.init();  
    }
    
    /** 
     * Returns the Redis session keys 
     * prefix. 
     * @return The prefix 
     */  
    public String getKeyPrefix() {  
        return keyPrefix;  
    }  
  
    /** 
     * Sets the Redis sessions key  
     * prefix. 
     * @param keyPrefix The prefix 
     */  
    public void setKeyPrefix(String keyPrefix) {  
        this.keyPrefix = keyPrefix;  
    }  
 
    /**
     * 获取redis中的session key
     * 
     * @param sessionId The id of session
     * @return The key of session 
     */
    protected String getRedisSessionKey(Serializable sessionId) {
        return this.keyPrefix + sessionId;
    }
    
    public JedisShiroSessionRepository() {
 
    }
 
    // public static void main(String[] args) {
    // Jedis jj = new Jedis("localhost");
    // //jj.set("key2", "232323231=========");
    // String ss = jj.get("key1");
    // System.out.println(jj.get("key2"));
    // System.out.println(ss);
    // }
}
