/*
 * Copyright (c) 2018 (https://github.com/hiwepy).
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
package org.apache.shiro.biz.authc.pam;

import org.apache.commons.collections.CollectionUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class DefaultModularRealmAuthenticator extends ModularRealmAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(DefaultModularRealmAuthenticator.class);

	@Override
	protected AuthenticationInfo doAuthenticate(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		
		this.assertRealmsConfigured();
		
		Collection<Realm> realms = this.getRealms();
		
		if (CollectionUtils.isEmpty(realms)) {
			throw new IllegalStateException("Configuration error:  No realms support token type:" + authenticationToken.getClass());
		}
		
		if (realms.size() == 1) {
			return this.doSingleRealmAuthentication(realms.iterator().next(), authenticationToken);
		} else {
			//获得匹配的Realm
			List<Realm> supportRealms = this.filterSupportRealms(realms, authenticationToken);
			if(CollectionUtils.isEmpty(supportRealms)) {
				throw new IllegalStateException("Configuration error:  No realms support token type:" + authenticationToken.getClass());
			}else if(supportRealms.size() == 1) {
				//只有一个匹配
				return this.doSingleRealmAuthentication(supportRealms.iterator().next(), authenticationToken);
			}else {
				//具有多个匹配，此时提醒开发者有可能会导致验证时的用户自定义异常丢失
				if(logger.isWarnEnabled()) {
					logger.warn("token类型为"+authenticationToken.getClass().getName()+"有超多一个对应的Realm处理，有可能会导致认证时用户自定义认证异常丢失，请检查核对配置文件！！！");
				}
				return this.doMultiRealmAuthentication(realms, authenticationToken);				
			}
		}
	}
	
	private List<Realm> filterSupportRealms(Collection<Realm> realms, AuthenticationToken authenticationToken) {
		List<Realm> supportRealms = new ArrayList<Realm>(realms);
		Iterator<Realm> it = supportRealms.iterator();
		while(it.hasNext()) {
			Realm r = it.next();
			if(!r.supports(authenticationToken)) {
				it.remove();
			}
		}
		return supportRealms;
	}
	

}
