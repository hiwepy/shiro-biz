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
package org.apache.shiro.biz.authz.principal;

import java.io.Serializable;

/**
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class ShiroRolePermssion implements Serializable {

	protected String roleId;
	protected String permissionId;

    public String getRoleId() {
        return roleId;
    }

    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    public String getPermissionId() {
        return permissionId;
    }

    public void setPermissionId(String permissionId) {
        this.permissionId = permissionId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o){
        	return true;
        }
        if (o == null || getClass() != o.getClass()){
        	return false;
        }
        ShiroRolePermssion that = (ShiroRolePermssion) o;
        if (permissionId != null ? !permissionId.equals(that.getPermissionId()) : that.getPermissionId() != null){
        	return false;
        }
        if (roleId != null ? !roleId.equals(that.getRoleId()) : that.getRoleId() != null) {
        	return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int result = roleId != null ? roleId.hashCode() : 0;
        result = 31 * result + (permissionId != null ? permissionId.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
		return "RolePermssion {" + "roleId=" + roleId + ", permissionId=" + permissionId + '}';
    }
}
