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
package org.apache.shiro.biz.principal;

import java.io.Serializable;

/**
 * 
 * @className	： ShiroRole
 * @description	： TODO(描述这个类的作用)
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 * @date		： 2017年9月12日 下午11:28:25
 * @version 	V1.0
 */
@SuppressWarnings("serial")
public class ShiroRole implements Serializable {
	
	protected String id;
    protected String role; //角色标识 程序中判断使用,如"admin"
    protected String description; //角色描述,UI界面显示使用
    protected Boolean available = Boolean.FALSE; //是否可用,如果不可用将不会添加给用户

    public ShiroRole() {
    }

    public ShiroRole(String role, String description, Boolean available) {
        this.role = role;
        this.description = description;
        this.available = available;
    }

    public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
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
        if (this == o) { 
        	return true;
        }
        if (o == null || getClass() != o.getClass()) {
        	return false;
        }
        ShiroRole role = (ShiroRole) o;
        if (id != null ? !id.equals(role.getId()) : role.getId() != null) {
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
		return "Role {" + "id=" + id + ", role='" + role + '\'' + ", description='" + description + '\'' + ", available=" + available + '}';
    }
}
