/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
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
package org.apache.shiro.biz.authz.principal;

import com.github.hiwepy.jwt.JwtPayload.RolePair;
import com.google.common.collect.Sets;
import org.apache.commons.collections.CollectionUtils;

import java.util.List;
import java.util.Set;

public abstract class ShiroPrincipalRepositoryImpl implements ShiroPrincipalRepository {

	@Override
	public Set<String> getRoles(Object principal) {
		Set<String> sets = Sets.newHashSet();
		if(principal instanceof ShiroPrincipal) {
			List<RolePair> roles = ((ShiroPrincipal)principal).getRoles();
			if(CollectionUtils.isNotEmpty(roles)) {
				for (RolePair role : roles) {
					sets.add(role.getKey());
				}
			}
		}
		return sets;
	}

	@Override
	public Set<String> getRoles(Set<Object> principals) {
		Set<String> sets = Sets.newHashSet();
		for (Object principal : principals) {
			if(principal instanceof ShiroPrincipal) {
				List<RolePair> roles = ((ShiroPrincipal)principal).getRoles();
				if(CollectionUtils.isNotEmpty(roles)) {
					for (RolePair role : roles) {
						sets.add(role.getKey());
					}
				}
			}
		}
		return sets;
	}

	@Override
	public Set<String> getPermissions(Object principal) {
		Set<String> sets = Sets.newHashSet();
		if(principal instanceof ShiroPrincipal) {
			sets.addAll(((ShiroPrincipal)principal).getPerms());
		}
		return sets;
	}

	@Override
	public  Set<String> getPermissions(Set<Object> principals) {
		Set<String> sets = Sets.newHashSet();
		for (Object principal : principals) {
			if(principal instanceof ShiroPrincipal) {
				sets.addAll(((ShiroPrincipal)principal).getPerms());
			}
		}
		return sets;
	}
	
	@Override
	public void doLock(Object principal) {
		// do nothing
	}
	
}
