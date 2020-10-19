package com.sxt.shiro;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class TestCode {

    @Test
    public void test01(){
        //1.创建一个SecurityManager 安全管理对象
        IniSecurityManagerFactory iniSecurityManagerFactory = new IniSecurityManagerFactory("classpath:shiro-config.ini");
        SecurityManager securityManager = iniSecurityManagerFactory.getInstance();
        //2. 将工厂对象和当前对象绑定
        SecurityUtils.setSecurityManager(securityManager);

        //3. 从当前线程获取主题对象
        Subject subject = SecurityUtils.getSubject();

        //4. 判断是否认证
        boolean authenticated = subject.isAuthenticated();
        System.out.println("认证前："+authenticated);
        if (!authenticated) {
            //5. 如果没有认证，那么进行认证（登录）
            //创建Token（令牌），封装该身份（账号）和凭证（密码）
            AuthenticationToken usernamePassworkToken = new UsernamePasswordToken("zhangsan","1234");
            try {
                //认证（登录）
                subject.login(usernamePassworkToken);
                /**
                 * 认证失败会抛出异常：
                 * 1. 身份不存在：org.apache.shiro.authc.UnknownAccountException
                 * 2. 密码错误：org.apache.shiro.authc.IncorrectCredentialsException
                 *
                 */

                //获取认证结果
                authenticated = subject.isAuthenticated();
                System.out.println("认证后："+authenticated);
            } catch (UnknownAccountException e) {
                System.out.println("账号不存在");
            } catch (IncorrectCredentialsException e){
                System.out.println("密码错误");
            }
        }

        //6. 获取认证身份信息(bean对象）
        Object principal = subject.getPrincipal();
        System.out.println("principal = " + principal);
        //7. 退出认证（退出登录）
        subject.logout();
        System.out.println("退出认证后："+authenticated);

    }
}
