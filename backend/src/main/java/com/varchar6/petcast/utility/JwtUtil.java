package com.varchar6.petcast.utility;

import com.varchar6.petcast.domain.member.query.service.MemberAuthenticationService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtUtil {
    private final Key key;
    private final MemberAuthenticationService memberAuthenticationService;

    public JwtUtil(@Value("${token.secret}") String secretKey, MemberAuthenticationService memberAuthenticationService) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.memberAuthenticationService = memberAuthenticationService;
    }

    public boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key).build()
                    .parseClaimsJws(token);
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid access token {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.info("Expired access token {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported access token {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.info("Empty access token {}", e.getMessage());
        }
        return true;
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        Collection<? extends GrantedAuthority> authorities = null;

        if (claims.get("authorities") != null) {
            authorities = Arrays.stream(
                            claims.get("authorities").toString()
                                    .replace("[", "")
                                    .replace("]", "")
                                    .split(", ")
                    )
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        } else {
            throw new IllegalArgumentException("No authorities found in token");
        }
        UserDetails savedUser = memberAuthenticationService.loadUserByUsername(getUserId(token));
        return new UsernamePasswordAuthenticationToken(
                savedUser,
                savedUser.getPassword(),
                authorities
        );
    }

    public Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key).build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUserId(String token)  {
        return parseClaims(token).getSubject();
    }
}
