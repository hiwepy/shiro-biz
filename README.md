# shiro-biz

## 说明


 > 基于Shiro的基础扩展，以便方便业务开发

###Subject：

主体，可以看到主体可以是任何可以与应用交互的“用户”；

###SecurityManager：

相当于SpringMVC中的DispatcherServlet或者Struts2中的FilterDispatcher；是Shiro的心脏；所有具体的交互都通过SecurityManager进行控制；它管理着所有Subject、且负责进行认证和授权、及会话、缓存的管理。

###Authenticator：

认证器，负责主体认证的，这是一个扩展点，如果用户觉得Shiro默认的不好，可以自定义实现；其需要认证策略（Authentication Strategy），即什么情况下算用户认证通过了；

###Authrizer：

授权器，或者访问控制器，用来决定主体是否有权限进行相应的操作；即控制着用户能访问应用中的哪些功能；
Realm：可以有1个或多个Realm，可以认为是安全实体数据源，即用于获取安全实体的；可以是JDBC实现，也可以是LDAP实现，或者内存实现等等；由用户提供；注意：Shiro不知道你的用户/权限存储在哪及以何种格式存储；所以我们一般在应用中都需要实现自己的Realm；

###SessionManager：

如果写过Servlet就应该知道Session的概念，Session呢需要有人去管理它的生命周期，这个组件就是SessionManager；而Shiro并不仅仅可以用在Web环境，也可以用在如普通的JavaSE环境、EJB等环境；所有呢，Shiro就抽象了一个自己的Session来管理主体与应用之间交互的数据；这样的话，比如我们在Web环境用，刚开始是一台Web服务器；接着又上了台EJB服务器；这时想把两台服务器的会话数据放到一个地方，这个时候就可以实现自己的分布式会话（如把数据放到Memcached服务器）；

###SessionDAO：

DAO大家都用过，数据访问对象，用于会话的CRUD，比如我们想把Session保存到数据库，那么可以实现自己的SessionDAO，通过如JDBC写到数据库；比如想把Session放到Memcached中，可以实现自己的Memcached SessionDAO；另外SessionDAO中可以使用Cache进行缓存，以提高性能；

###CacheManager：

缓存控制器，来管理如用户、角色、权限等的缓存的；因为这些数据基本上很少去改变，放到缓存中后可以提高访问的性能

###Cryptography：

密码模块，Shiro提高了一些常见的加密组件用于如密码加密/解密的。


```java
//获取唯一主键对象
    Object uniquely = token.getPrincipal();

    Principal principal = this.getPrincipal(uniquely);
    /*
        如果身份验证失败请捕获AuthenticationException或其子类，常见的如：
        	DisabledAccountException（禁用的帐号）、
        	LockedAccountException（锁定的帐号）、
        	UnknownAccountException（错误的帐号）、
        	ExcessiveAttemptsException（登录失败次数过多）、
        	IncorrectCredentialsException （错误的凭证）、
        	ExpiredCredentialsException（过期的凭证）等，具体请查看其继承关系；
        	对于页面的错误消息展示，最好使用如“用户名/密码错误”而不是“用户名错误”/“密码错误”，防止一些恶意用户非法扫描帐号库；
       */
     if(principal == null) {
        //没找到帐号
        throw new UnknownAccountException(PrincipalRealmEnum.UNKONWN_ACCOUNT.getText());
        }
        
        if(Boolean.TRUE.equals(principal.getDisabled())) {
       //帐号锁定
            throw new DisabledAccountException(PrincipalRealmEnum.DISABLED_ACCOUNT.getText()); 
        }
        
        if(Boolean.TRUE.equals(principal.getLocked())) {
        //帐号锁定
            throw new LockedAccountException(PrincipalRealmEnum.LOCKED_ACCOUNT.getText());
        }

        //交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配，如果觉得人家的不好可以自定义实现
        
        SimpleAccount add  = new SimpleAccount(principal, hashedCredentials, credentialsSalt, realmName)
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                principal.getUsername(), //用户名
                principal.getPassword(), //密码
                ByteSource.Util.bytes(principal.getCredentialsSalt()),//salt=username+salt
                getName()  //realm name
       );
```

### Maven Dependency

``` xml
<dependency>
	<groupId>com.github.hiwepy</groupId>
	<artifactId>shiro-biz</artifactId>
	<version>1.1.9.RELEASE</version>
</dependency>
```
