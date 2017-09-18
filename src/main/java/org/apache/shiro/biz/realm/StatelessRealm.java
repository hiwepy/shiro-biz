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
package org.apache.shiro.biz.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.biz.authc.token.StatelessToken;
import org.apache.shiro.biz.utils.HmacSHA256Utils;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class StatelessRealm extends AuthorizingRealm {  
	
    public boolean supports(AuthenticationToken token) {  
        //仅支持StatelessToken类型的Token  
        return token instanceof StatelessToken;  
    }  
    
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {  
        //根据用户名查找角色，请根据需求实现  
        String username = (String) principals.getPrimaryPrincipal();  
        SimpleAuthorizationInfo authorizationInfo =  new SimpleAuthorizationInfo();  
        authorizationInfo.addRole("admin");  
        return authorizationInfo;  
    }  
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {  
        StatelessToken statelessToken = (StatelessToken) token;  
        String username = statelessToken.getUsername();  
        String key = getKey(username);//根据用户名获取密钥（和客户端的一样）  
        //在服务器端生成客户端参数消息摘要  
        String serverDigest = HmacSHA256Utils.digest(key, statelessToken.getParams());  
        //然后进行客户端消息摘要和服务器端消息摘要的匹配  
        return new SimpleAuthenticationInfo(  
                username,  
                serverDigest,  
                getName());  
    }  
      
    private String getKey(String username) {//得到密钥，此处硬编码一个  
        if("admin".equals(username)) {  
            return "dadadswdewq2ewdwqdwadsadasd";  
        }  
        return null;  
    }  
}   