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
package org.apache.shiro.biz.principal;

import java.io.Serializable;

/**
 * Shiro 认证对象
 * @author <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class ShiroPermission implements Serializable {
	
	protected String id;
    protected String permission; //权限标识 程序中判断使用,如"user:create"
    protected String description; //权限描述,UI界面显示使用
    protected Boolean available = Boolean.FALSE; //是否可用,如果不可用将不会添加给用户

    public ShiroPermission() {
    }

    public ShiroPermission(String permission, String description, Boolean available) {
        this.permission = permission;
        this.description = description;
        this.available = available;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Boolean getAvailable() {
        return available;
    }

    public void setAvailable(Boolean available) {
        this.available = available;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o){
        	return true;
        }
        if (o == null || getClass() != o.getClass()){
        	return false;
        }
        ShiroPermission permission = (ShiroPermission) o;
        if (id != null ? !id.equals(permission.getId()) : permission.getId() != null){
        	return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

    @Override
    public String toString() {
		return "Permission{" + "id=" + id + ", permission='" + permission + '\'' + ", description='" + description + '\'' + ", available=" + available + '}';
    }
}
