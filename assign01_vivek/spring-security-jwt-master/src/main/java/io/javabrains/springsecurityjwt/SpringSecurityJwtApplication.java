package io.javabrains.springsecurityjwt;

import io.javabrains.springsecurityjwt.filters.JwtRequestFilter;
import io.javabrains.springsecurityjwt.models.AuthenticationRequest;
import io.javabrains.springsecurityjwt.models.AuthenticationResponse;
import io.javabrains.springsecurityjwt.util.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.Header;
import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

@SpringBootApplication
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

}

@RestController
class HelloWorldController {
    public String Client_id = "10000";
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @RequestMapping(value = "/")
    public ModelAndView firstpage(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("start");
        resp.sendRedirect(req.getContextPath() + "/client");
        return mv;
    }

    @RequestMapping(value = "/client")
    public ModelAndView client(@CookieValue(value = "10000", defaultValue = "0") String cookieval, HttpServletRequest http, HttpServletResponse response) throws IOException, InterruptedException {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("client");
        if (!cookieval.equals("0")) {
            //previous login exist
            mv.addObject("jwt", cookieval);
            mv.addObject("expiry",jwtTokenUtil.extractExpiration(cookieval));
        } else {
            //redirect to login
            TimeUnit.SECONDS.sleep(2);
            response.sendRedirect(http.getContextPath() + "/login?Clientid" + Client_id + "&uri=/callback");
        }
        return mv;
    }

    @RequestMapping(value = "/login")
    public ModelAndView login(String Clientid, String uri) {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("loginForm");
        return mv;
    }

    @RequestMapping(value = "/addAuthenticationRequest")
    public ResponseEntity<?> addAuthenticationRequest(AuthenticationRequest accinfo, HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("login");
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(accinfo.getUsername(), accinfo.getPassword()));
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }
        final UserDetails userDetails = userDetailsService.loadUserByUsername(accinfo.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);
        mv.addObject("response", jwt);

        Cookie mycookie = new Cookie("10000", jwt);
        mycookie.setMaxAge(60 * 60);
        resp.addCookie(mycookie);
        resp.sendRedirect(req.getContextPath() + "/callback?id_token=" + jwt + "&username=" + accinfo.getUsername());
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    @RequestMapping(value = "/callback")
    public ModelAndView callback(String id_token, String username) {
        ModelAndView mv = new ModelAndView();
        mv.addObject("timeleft", jwtTokenUtil.extractExpiration(id_token));
        mv.addObject("token", id_token);
        mv.addObject("extusername", jwtTokenUtil.extractUsername(id_token));
        mv.addObject("givenusername", username);
        mv.addObject("expired", jwtTokenUtil.isTokenExpired(id_token));
        mv.addObject("validate", jwtTokenUtil.validateToken(id_token, username));
        mv.setViewName("callback");
        return mv;
    }
}


@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService myUserDetailsService;
    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {

        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable().authorizeRequests().antMatchers("/login", "/client", "/addAuthenticationRequest", "/", "/callback").permitAll().anyRequest().authenticated().and().
                exceptionHandling().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

}