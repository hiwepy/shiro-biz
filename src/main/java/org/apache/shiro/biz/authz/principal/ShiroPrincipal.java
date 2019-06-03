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
package org.apache.shiro.biz.authz.principal;

import java.io.Serializable;
import java.util.Set;

/**
 * @author <a href="https://github.com/vindell">vindell</a>
 */
@SuppressWarnings("serial")
public class ShiroPrincipal implements Cloneable, Serializable {
	
	/**
	 * 用户ID（用户来源表Id）
	 */
	protected String userid;
	/**
	 * 用户Key
	 */
	protected String userkey;
	/**
	 * 用户名称
	 */
	protected String username;
	/**
	 * 用户密码
	 */
	protected String password;
	/**
	 * 用户密码盐：用于密码加解密
	 */
    protected String salt;
    /**
	 * 用户秘钥：用于用户JWT加解密
	 */
	private String secret;
	/**
	 * 用户别名（昵称）
	 */
	private String alias;
	/**
	 * 用户拥有角色列表
	 */
	private Set<String> roles;
	/**
	 * 用户权限标记列表
	 */
	private Set<String> perms;
	/**
	 * 用户是否可用
	 */
    protected boolean disabled = Boolean.FALSE;
    /**
	 * 用户是否锁定
	 */
    protected boolean locked = Boolean.FALSE;
    /**
   	 * 用户是否首次登录
   	 */
    protected boolean initial = Boolean.FALSE;
    
    public ShiroPrincipal() {
    }

    public ShiroPrincipal(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUserid() {
		return userid;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	public String getUserkey() {
		return userkey;
	}

	public void setUserkey(String userkey) {
		this.userkey = userkey;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getCredentialsSalt() {
        return username + salt;
    }

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}
	
	public Set<String> getRoles() {
		return roles;
	}

	public void setRoles(Set<String> roles) {
		this.roles = roles;
	}

	public Set<String> getPerms() {
		return perms;
	}

	public void setPerms(Set<String> perms) {
		this.perms = perms;
	}
	
	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public boolean isDisabled() {
		return disabled;
	}

	public void setDisabled(boolean disabled) {
		this.disabled = disabled;
	}

	public boolean isLocked() {
		return locked;
	}

	public void setLocked(boolean locked) {
		this.locked = locked;
	}
	
	public boolean isInitial() {
		return initial;
	}

	public void setInitial(boolean initial) {
		this.initial = initial;
	}

	@Override
    public boolean equals(Object o) {
        if (this == o) {
        	return true;
        }
        if (o == null || getClass() != o.getClass()){
        	return false;
        }
        ShiroPrincipal user = (ShiroPrincipal) o;
        if (userid != null ? !userid.equals(user.getUserid()) : user.getUserid() != null){
        	return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        return userid != null ? userid.hashCode() : 0;
    }

    @Override
    public String toString() {
		return " User {" + "userid=" + userid + ", username='" + username + '\'' + ", password='" + password + '\'' + ", salt='" + salt + '\'' + ", disabled='" + disabled + '\'' + ", locked=" + locked + '}';
    }
    
}
