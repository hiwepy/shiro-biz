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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;


import com.github.hiwepy.jwt.JwtPayload.RolePair;

/**
 * @author <a href="https://github.com/hiwepy">hiwepy</a>
 */
@SuppressWarnings("serial")
public class ShiroPrincipal implements Cloneable, Serializable {
	
	/**
	 * 用户ID（用户来源表Id）
	 */
	private String userid;
	/**
	 * 用户Key：用户业务表中的唯一ID
	 */
	private String userkey;
	/**
	 * 用户Code：用户业务表中的唯一编码
	 */
	private String usercode;
	/**
	 * 用户名称
	 */
	private String username;
	/**
	 * 用户密码
	 */
	private String password;
	/**
	 * 用户密码盐：用于密码加解密
	 */
	private String salt;
	/**
	 * 用户秘钥：用于用户JWT加解密
	 */
	private String secret;
	/**
	 * 用户别名（昵称）
	 */
	@Deprecated
	private String alias;
	private String nickname;
	/**
	 * 用户角色ID
	 */
	private String roleid;
	/**
	 * 用户角色Key
	 */
	private String role;
	/**
	 * 用户人脸识别ID
	 */
	private String faceId;
	/**
	 * 用户拥有角色列表
	 */
	private List<RolePair> roles;
	/**
	 * 用户权限标记列表
	 */
	private Set<String> perms;
	/**
	 * 用户数据
	 */
	private Map<String, Object> profile = new HashMap<String, Object>();
	/**
	 * 用户是否可用
	 */
    private boolean disabled = Boolean.FALSE;
    /**
	 * 用户是否锁定
	 */
    private boolean locked = Boolean.FALSE;
    /**
   	 * 用户是否首次登录
   	 */
    private boolean initial = Boolean.FALSE;
    /**
	 * 用户是否扫脸登录
	 */
	private boolean face = Boolean.FALSE;
	
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

	public String getUsercode() {
		return usercode;
	}

	public void setUsercode(String usercode) {
		this.usercode = usercode;
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
	
	public String getNickname() {
		return nickname;
	}

	public void setNickname(String nickname) {
		this.nickname = nickname;
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

	@Deprecated
	public String getAlias() {
		return alias;
	}

	@Deprecated
	public void setAlias(String alias) {
		this.alias = alias;
	}

	public String getRoleid() {
		return roleid;
	}

	public void setRoleid(String roleid) {
		this.roleid = roleid;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getFaceId() {
		return faceId;
	}

	public void setFaceId(String faceId) {
		this.faceId = faceId;
	}

	public List<RolePair> getRoles() {
		return roles;
	}

	public void setRoles(List<RolePair> roles) {
		this.roles = roles;
	}

	public Set<String> getPerms() {
		return perms;
	}

	public void setPerms(Set<String> perms) {
		this.perms = perms;
	}

	public Map<String, Object> getProfile() {
		return profile;
	}

	public void setProfile(Map<String, Object> profile) {
		this.profile = profile;
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

	public boolean isFace() {
		return face;
	}

	public void setFace(boolean face) {
		this.face = face;
	}

	public boolean isAdmin() {
		if(!StringUtils.isNoneBlank(role)) {
			return false;
		}
		if(CollectionUtils.isEmpty(roles)) {
			return false;
		}
		return CollectionUtils.contains(getRoles().iterator(), "admin") || StringUtils.equalsIgnoreCase("admin", this.getRole()) || StringUtils.equalsIgnoreCase("admin", this.getRoleid());
	}
	
	public boolean hasRole(String role) {
		if(!StringUtils.isNoneBlank(role)) {
			return false;
		}
		if(CollectionUtils.isEmpty(roles)) {
			return false;
		}
		return roles.stream().anyMatch(entry -> StringUtils.equalsIgnoreCase(entry.getKey(), role));
	}
	
	public boolean hasAnyRole(String... roles) {
		if(!StringUtils.isNoneBlank(roles)) {
			return false;
		}
		if(CollectionUtils.isEmpty(getRoles())) {
			return false;
		}
		return CollectionUtils.containsAny(getRoles(), Arrays.asList(roles));
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
    
    public Map<String, Object> toClaims(){
		
		Map<String, Object> claims = new HashMap<>(13);
		
		claims.put("role", this.getRole());
		claims.put("roleid", this.getRoleid());
		claims.put("roles", this.getRoles());
		claims.put("perms", this.getPerms());
		claims.put("alias", this.getAlias());
		claims.put("nickname", this.getNickname());
		claims.put("userid", this.getUserid());
		claims.put("username", this.getUsername());
		claims.put("userkey", this.getUserkey());
		claims.put("usercode", this.getUsercode());
		claims.put("initial", this.isInitial());
		claims.put("faced", this.isFace());
		claims.put("faceid", this.getFaceId());
		if (CollectionUtils.isEmpty(this.getProfile())) {
			claims.put("profile", new HashMap<>(0));
		} else {
			claims.put("profile", this.getProfile());
		}
		return claims;
		
	}
    
}
