package com.sp.fc.web.config;


import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthDetails customAuthDetails;


    //로그인 권한에 대한 custom 정보를 띄어주기 위함.
    public SecurityConfig(CustomAuthDetails customAuthDetails) {
        this.customAuthDetails = customAuthDetails;
    }

    // 테스트를 위한 inMemory에 사용자 권한 아이디를 지정해줌
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser(
                        User.withDefaultPasswordEncoder()
                        .username("user1")
                        .password("1111")
                        .roles("USER")
                ).withUser(
                User.withDefaultPasswordEncoder()
                        .username("admin1")
                        .password("2222")
                        .roles("ADMIN")
        );
    }
    //ADMIN이 USER의 페이지까지 읽을 수 있게 권한이 상위에 있다는 것을 설정함.
    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            .antMatchers("/").permitAll() //기본경로만 permitAll
                            .anyRequest().authenticated(); //이후 경로들은 권한이 있어야함 가능
                })
                .formLogin(
                        login -> login.loginPage("/login")
                        .permitAll()  //로그인페이지도 모든 사용자가 접근 가능하게 따로 permitAll
                        .defaultSuccessUrl("/",false) //돌아갈 경로가 없으면 default경로로 "/" 로 이동하고 always false 를 줘서 접근한 경로로 로그인 후 다시 이동함.
                        .failureUrl("/login-error")  //로그인 실패하면 /login-error페이지로 이동함.
                        .authenticationDetailsSource(customAuthDetails)

                )
                .logout(logout->logout.logoutSuccessUrl("/")) //로그아웃에 성공하면 default경로로 이동함
                .exceptionHandling(exception->exception.accessDeniedPage("/access-denied"))//핸들링을 통해서 접근이 불가능한 경로에 대한 access-denied 페이지로 이동시킴.
                ;
    }

    //css, java_script, images, web_jars, favicon 등 아래의 경로를 웹 리소스 경로로 취급을 함.
    //security 때문에 막힌 css 등 문제들을 해결
    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }
}
