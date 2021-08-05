package com.ma.security.config;


import com.ma.security.service.impl.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.zalando.problem.spring.web.advice.security.SecurityProblemSupport;

import javax.sql.DataSource;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Import(SecurityProblemSupport.class)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationSuccessHandler myAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler myAuthenticationFailHander;
    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private SecurityProblemSupport securityProblemSupport;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .formLogin().loginPage("/loginPage").loginProcessingUrl("/form")
                .successHandler(myAuthenticationSuccessHandler)  //登录成功跳转
                .failureHandler(myAuthenticationFailHander)   //登录失败跳转
                .usernameParameter("username") //设置默认的请求参数名和前端进行绑定
                .passwordParameter("password")
                .permitAll()  //表单登录，permitAll()表示这个不需要验证 登录页面，登录失败页面
                .and()
                .logout()   //退出登录相关配置
                .logoutUrl("signOut")   //自定义退出登录页面
                //.logoutSuccessHandler() //退出成功后要做的操作（如记录日志），和logoutSuccessUrl互斥
                .logoutSuccessUrl("/index") //退出成功后跳转的页面
                //.deleteCookies("JSESSIONID")    //退出时要删除的Cookies的名字
                .and()
                .rememberMe()  //记住我功能
                .rememberMeParameter("remember-me").userDetailsService(userDetailsService)
                .tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(60)
                .and()
                .headers()  //页面里有需要通过iframe/frame引用的页面需要关闭
                .frameOptions()
                .disable()
                .and()
                .authorizeRequests()    //对授权请求进行配置
                //.antMatchers("/index").permitAll()  //这就表示 /index这个页面不需要权限认证，所有人都可以访问
                //.antMatchers("/whoim").hasRole("ADMIN") //这就表示/whoim的这个资源需要有ROLE_ADMIN的这个角色才能访问。不然就会提示拒绝访问
//                .antMatchers(HttpMethod.POST,"/user/*").hasRole("ADMIN")
//               .antMatchers(HttpMethod.GET,"/user/*").hasRole("USER")
                .anyRequest().access("@rbacService.hasPermission(request,authentication)")    //必须经过认证以后才能访问
                // .anyRequest().authenticated() //必须经过认证以后才能访问
                .and()
                .csrf().disable()  //取消默认csrf防护(web常见攻击方式) 使用下面的方式进行处理
                .exceptionHandling()  //异常请求
               // .authenticationEntryPoint("13")  //用来解决匿名用户访问无权限资源时的异常
                .accessDeniedHandler(securityProblemSupport);  //用来解决认证过的用户访问无权限资源时的异常
    }

    //在代码中写死用户名和密码
  /*  @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .passwordEncoder(passwordEncoder())
                .withUser("admin").password(passwordEncoder().encode("123456")).roles("ADMIN")
                .and()
                .withUser("test").password(passwordEncoder().encode("test123")).roles("USER");

    }*/

    @Autowired
    private MyAuthenticationProvider provider;  //注入我们自己的AuthenticationProvider

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(provider);
    }

    @Autowired
    private DataSource dataSource;   //是在application.properites

    /**
     * 记住我功能的token存取器配置
     *
     * @return
     */
    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }


}