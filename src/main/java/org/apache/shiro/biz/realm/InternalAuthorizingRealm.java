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
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authc.credential.PasswordService;
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
 * <b>内部账户抽象Realm</b> 
 * <p>公共需要做的事：1.记录日志；2.提高更高级api；3.封装内部处理逻辑；4.事件监听；</p>
 * @author <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("unchecked")
public abstract class InternalAuthorizingRealm extends AuthorizingRealm {
	
	private static final Logger LOG = LoggerFactory.getLogger(InternalAuthorizingRealm.class);

	//realm listeners
	protected List<PrincipalRealmListener> realmsListeners;
	
	protected PrincipalRepository repository;
	
	protected PasswordService passwordService = new DefaultPasswordService();  
    
	/**
	 * 获取授权信息;
	 * 
	 * @author 		：<a href="https://github.com/vindell">vindell</a>
	 * @param principals : PrincipalCollection是一个身份集合，因为我们现在就一个Realm，所以直接调用getPrimaryPrincipal得到之前传入的用户名即可；然后根据用户名调用UserService接口获取角色及权限信息。
	 * @return 授权信息
	 */
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

	/**
	 * 
	 *  获取身份验证相关信息
	 * 
	 *  <pre>
	 * 	首先根据传入的用户名获取User信息；然后如果user为空，那么抛出没找到帐号异常UnknownAccountException；
	 * 	如果user找到但锁定了抛出锁定异常LockedAccountException；
	 *  最后生成AuthenticationInfo信息，交给间接父类AuthenticatingRealm使用CredentialsMatcher进行判断密码是否匹配，如果不匹配将抛出密码错误异常IncorrectCredentialsException；
	 *  
	 *  另外如果密码重试此处太多将抛出超出重试次数异常ExcessiveAttemptsException；
	 *  在组装SimpleAuthenticationInfo信息时，需要传入：
	 *  	身份信息（用户名）、凭据（密文密码）、盐（username+salt），
	 *  CredentialsMatcher使用盐加密传入的明文密码和此处的密文密码进行匹配。
	 * 
	 *  </pre>
	 * 
	 * @author ：<a href="https://github.com/vindell">vindell</a>
	 * @param token 认证Token
	 * @return 授权信息
	 * @throws AuthenticationException 认证异常
	 */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    	
    	LOG.info("Handle authentication token {}.", new Object[] { token });
    	
    	
    	AuthenticationException ex = null;
    	AuthenticationInfo info = null;
    	try {
    		info = this.doGetInternalAuthenticationInfo(token);
		} catch (AuthenticationException e) {
			ex = e;
		}
		
		//调用事件监听器
		if(getRealmsListeners() != null && getRealmsListeners().size() > 0){
			for (PrincipalRealmListener realmListener : getRealmsListeners()) {
				if(ex != null || null == info){
					realmListener.onAuthenticationFail(token);
				}else{
					realmListener.onAuthenticationSuccess(info, SecurityUtils.getSubject().getSession());
				}
			}
		}
		
		if(ex != null){
			throw ex;
		}
		
		return info;
    }
    
	protected AuthenticationInfo doGetInternalAuthenticationInfo(AuthenticationToken token){
		SimpleAccount account = null;
		// do real thing
		// new delegate authentication token and invoke doAuthc method
		DelegateAuthenticationInfo delegateAuthcInfo = getRepository().getAuthenticationInfo(this.createDelegateAuthenticationToken(token));
		if (delegateAuthcInfo != null) {
			account = new SimpleAccount(
					//用户名
					delegateAuthcInfo.getPrincipal(),
					//加密后的密码
					getPasswordService().encryptPassword(delegateAuthcInfo.getCredentials()), 
					//盐是用户名+随机数 
					ByteSource.Util.bytes(delegateAuthcInfo.getCredentialsSalt()),
					getName());
		}
		return account;
	}

	protected abstract DelegateAuthenticationToken createDelegateAuthenticationToken(AuthenticationToken token);
	
	public void clearAuthorizationCache(){
		clearCachedAuthorizationInfo(SecurityUtils.getSubject().getPrincipals());
	}
	
	public PrincipalRepository getRepository() {
		return repository;
	}

	public void setRepository(PrincipalRepository repository) {
		this.repository = repository;
	}

	public PasswordService getPasswordService() {
		return passwordService;
	}

	public List<PrincipalRealmListener> getRealmsListeners() {
		return realmsListeners;
	}

	public void setRealmsListeners(List<PrincipalRealmListener> realmsListeners) {
		this.realmsListeners = realmsListeners;
	}

	public void setPasswordService(PasswordService passwordService) {  
		 this.passwordService = passwordService;  
	} 

	
}
