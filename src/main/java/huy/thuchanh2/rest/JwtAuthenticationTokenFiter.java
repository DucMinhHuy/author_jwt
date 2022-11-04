package huy.thuchanh2.rest;

import huy.thuchanh2.service.JwtService;
import huy.thuchanh2.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtAuthenticationTokenFiter extends UsernamePasswordAuthenticationFilter {
    private final static String token_header="authorization";
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserService userService;
    @Autowired
    @Override
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest=(HttpServletRequest) request;
        String authToken =httpRequest.getHeader(token_header);
        if(jwtService.validateTokenLogin(authToken)){
            String username= jwtService.getUsernameFromToken(authToken);
//            huy.thuchanh2.entities.User user=
            huy.thuchanh2.entities.User user=userService.loadUserByusername(username);
            if(user!=null){
                boolean enabled=true;
                boolean accountNonExpired=true;
                boolean cre=true;
                boolean acc=true;
                UserDetails userDetails=new org.springframework.security.core.userdetails.User(username,user.getPassword(),enabled,accountNonExpired,cre,acc,user.getAuthorities());
                UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        chain.doFilter(request,response);
    }
}
