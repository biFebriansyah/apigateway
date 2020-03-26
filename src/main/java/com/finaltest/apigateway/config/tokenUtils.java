package com.finaltest.apigateway.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import com.auth0.jwt.JWT;

@Service
public class tokenUtils implements Serializable {

    @Value("${jwt.secret}")
    String jwtKey;

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) throws JWTDecodeException {

//        return getClaimFromToken(token, Claims::getSubject);
        DecodedJWT jwt = JWT.decode(token);
        Claim claim = jwt.getClaim("email");
        return claim.asString();

    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) throws JWTVerificationException {
        final String username = getUsernameFromToken(token);
        try {
            String user = JWT.require(Algorithm.HMAC256(jwtKey))
                    .build()
                    .verify(token)
                    .getSubject();

            System.out.println(user);
            if (user != null) {
                return true;
            } else {
                return false;
            }
        } catch (JWTVerificationException er) {
            System.out.println(er.getMessage());
            throw er;
        }
    }
}
