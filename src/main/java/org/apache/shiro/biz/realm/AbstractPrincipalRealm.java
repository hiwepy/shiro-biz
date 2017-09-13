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

import java.util.List;
import java.util.Set;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.biz.authc.DelegateAuthenticationInfo;
import org.apache.shiro.biz.authc.token.DelegateAuthenticationToken;
import org.apache.shiro.biz.principal.PrincipalRepository;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @className	： AbstractPrincipalRealm
 * @description	：  抽象realm，个业务系统自己实现接口中的方法
 * 公共需要做的事：1.记录日志；2.提高更高级api；3.封装内部处理逻辑；4.事件监听；
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年8月26日 下午10:01:27
 * @version 	V1.0
 */
@SuppressWarnings("unchecked")
public abstract class AbstractPrincipalRealm extends AuthorizingRealm {
	
	private static final Logger LOG = LoggerFactory.getLogger(AbstractPrincipalRealm.class);

	//realm listeners
	protected List<PrincipalRealmListener> realmsListeners;
	
	protected PrincipalRepository repository;
    
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    	
    	if(principals == null || principals.isEmpty()){
			return null;
		}
    	
    	Set<String> permissionsSet, rolesSet = null;
		if(principals.asList().size() <= 1){
			permissionsSet = getRepository().getPermissions(principals.getPrimaryPrincipal());
			rolesSet = getRepository().getRoles(principals.getPrimaryPrincipal());
		}else{
			permissionsSet = getRepository().getPermissions(principals.asSet());
			rolesSet = getRepository().getRoles(principals.asSet());
		}
		
    	SimpleAccount account = new SimpleAccount();
    	account.setRoles(rolesSet);
    	account.setStringPermissions(permissionsSet);
        return account;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    	
    	LOG.info("Handle authentication token {}.", new Object[] { token });
    	
    	
    	AuthenticationException ex = null;
    	SimpleAccount account = null;
    	try {
			// do real thing
			// new delegate authentication token and invoke doAuthc method
			DelegateAuthenticationInfo delegateAuthcInfo = getRepository().getAuthenticationInfo(this.createDelegateAuthenticationToken(token));
			if (delegateAuthcInfo != null) {
				account = new SimpleAccount(delegateAuthcInfo.getPrincipal(),
						delegateAuthcInfo.getCredentials(),
						ByteSource.Util.bytes(delegateAuthcInfo.getCredentialsSalt()),
						getName());
			}
		} catch (AuthenticationException e) {
			ex = e;
		}
		
		//调用事件监听器
		if(getRealmsListeners() != null && getRealmsListeners().size() > 0){
			for (PrincipalRealmListener realmListener : getRealmsListeners()) {
				if(ex != null || null == account){
					realmListener.onAuthenticationFail(token);
				}else{
					realmListener.onAuthenticationSuccess(account, SecurityUtils.getSubject().getSession());
				}
			}
		}
		
		if(ex != null){
			throw ex;
		}
		
		return account;
        
    }

	public void clearAuthorizationCache(){
		clearCachedAuthorizationInfo(SecurityUtils.getSubject().getPrincipals());
	}
    
	protected abstract DelegateAuthenticationToken createDelegateAuthenticationToken(AuthenticationToken token);
	
	
	public PrincipalRepository getRepository() {
		return repository;
	}

	public void setRepository(PrincipalRepository repository) {
		this.repository = repository;
	}

	public List<PrincipalRealmListener> getRealmsListeners() {
		return realmsListeners;
	}

	public void setRealmsListeners(List<PrincipalRealmListener> realmsListeners) {
		this.realmsListeners = realmsListeners;
	}

	
}
