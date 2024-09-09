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

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key).build()
                    .parseClaimsJws(token);
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT token {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.info("Empty JWT token {}", e.getMessage());
        }
        return true;
    }

    public Authentication getAuthentication(String token) {
        log.debug("token: {}", token);
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
        return new UsernamePasswordAuthenticationToken(
                memberAuthenticationService.loadUserByUsername(getUserId(token)),
                "",
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
