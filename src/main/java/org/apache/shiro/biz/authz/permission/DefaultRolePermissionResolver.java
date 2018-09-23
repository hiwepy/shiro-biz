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
package org.apache.shiro.biz.authz.permission;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.collections.MapUtils;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.RolePermissionResolver;
import org.apache.shiro.authz.permission.WildcardPermission;
import org.apache.shiro.biz.utils.StringUtils;

/**
 * @author <a href="https://github.com/vindell">vindell</a>
 */
public class DefaultRolePermissionResolver implements RolePermissionResolver {

	/**
	 * The default permissions for authenticated role
	 */
	private Map<String /* role */, String /* permissions */> defaultRolePermissions = new LinkedHashMap<String, String>();;
	
	@Override
    public Collection<Permission> resolvePermissionsInRole(String role) {
        if("admin".equals(role)) {
            return Arrays.asList((Permission) new WildcardPermission("*:*"));
        }
        if( MapUtils.isNotEmpty(defaultRolePermissions)) {
        	String permissions = defaultRolePermissions.get(role);
        	return StringUtils.hasText(permissions) ? Arrays.asList((Permission) new WildcardPermission(permissions)) : null;
        }
        return null;
    }

	public Map<String, String> getDefaultRolePermissions() {
		return defaultRolePermissions;
	}

	public void setDefaultRolePermissions(Map<String, String> defaultRolePermissions) {
		this.defaultRolePermissions = defaultRolePermissions;
	}
	
}
