package com.finaltest.apigateway.config;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.finaltest.apigateway.service.userDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class requestFilter extends OncePerRequestFilter {

    @Autowired
    tokenUtils TokenUtils;

    @Autowired
    userDetailService userDetailService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String reqHeader = request.getHeader("authtokne");
        String username = null;
        String token = null;


        if (reqHeader != null && reqHeader.startsWith("Bearer ")) {
            token = reqHeader.substring(7);
            try {
                username = TokenUtils.getUsernameFromToken(token);
                System.out.println(username);
            } catch (JWTDecodeException e) {
                System.out.println("error while Decode token");
                return;
            }

        }


        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                UserDetails userDetails = this.userDetailService.loadUserByUsername(username);
                if (TokenUtils.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
                            UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    usernamePasswordAuthenticationToken
                            .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                }

            } catch (NullPointerException nl) {
                return;

            } catch (JWTVerificationException er) {
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

}
