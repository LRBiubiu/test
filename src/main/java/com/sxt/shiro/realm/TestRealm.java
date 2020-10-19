package com.sxt.shiro.realm;

import com.sxt.shiro.bean.User;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.Arrays;
import java.util.List;

/**
 * 自定义 Realm
 * 继承 AuthorizingRealm 类（Realm接口的抽象实现类）
 */
public class TestRealm extends AuthorizingRealm {


    /**
     * 授权信息
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        return null;
    }


    /**
     * 认证信息
     *
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //1. 获取token 的身份（账号）
        String username = (String) token.getPrincipal();

        //2. 从数据库中查询User信息（模拟）
        List<String> userList = Arrays.asList("zhangsan","lisi","wangwu","zhaoliu");
        //3. 判断是否存在该账号
        //3.1 如果没有就直接返回 null
        if (!userList.contains(username)) {
            return null;
        }
        //3.2 如果存在，就获取数据库中的对应的对象（模拟获取数据库中的对象）
        User user = new User(username, "1234");
        //获取该用户的密码
        String password = user.getPassword();

        /**
         * SimpleAuthenticationInfo(Object principal, Object credentials, String realmName)
         * 认证信息对象构造方法相关属性：
         * Object principal：当前认证的身份（从数据库中获取到的bean）
         * Object credentials：当前认证的身份对应的凭证（从数据库对象中获取的密码）
         * String realmName：realm 的名称
         */
        //4. 创建认证信息对象并返回
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(user, password, this.getName());
        return authenticationInfo;

    }
}
