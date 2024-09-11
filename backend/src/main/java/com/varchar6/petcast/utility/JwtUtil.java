package com.varchar6.petcast.utility;

import com.varchar6.petcast.domain.member.query.service.MemberAuthenticationService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtUtil {
    private final Key key;
    private final Environment environment;
    private final MemberAuthenticationService memberAuthenticationService;

    public JwtUtil(
            @Value("${token.secret}") String secretKey,
            MemberAuthenticationService memberAuthenticationService,
            Environment environment
    ) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.memberAuthenticationService = memberAuthenticationService;
        this.environment = environment;
    }

    public boolean isTokenValidate(String token) {
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
        UserDetails savedUser = memberAuthenticationService.loadUserByUsername(getLoginId(token));
        return new UsernamePasswordAuthenticationToken(
                savedUser,
                savedUser.getPassword(),
                authorities
        );
    }

    public Claims parseClaims(String token) {
        log.debug("parseClaims called");
        return Jwts.parserBuilder()
                .setSigningKey(key).build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getLoginId(String token)  {
        log.debug("getLoginId called");
        return parseClaims(token).getSubject();
    }

    public String generateAccessToken(Authentication authentication) {
        return createToken(
                setClaims(authentication),
                environment.getProperty("token.access.expiration_time")
        );
    }

    public String generateRefreshToken(Authentication authentication) {
        return createToken(
                setClaims(authentication), environment.getProperty("token.refresh.expiration_time")
        );
    }

    private Claims setClaims(Authentication authentication) {
        Claims claims = Jwts.claims().setSubject(authentication.getName());
        claims.put(
                "authorities",
                authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        );
        return claims;
    }

    private String createToken(Claims claims, String tokenExpiredAt) {
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(
                        new Date(
                                System.currentTimeMillis()
                                        + Long.parseLong(
                                                Objects.requireNonNull(tokenExpiredAt)
                                )
                        )
                )
                .signWith(SignatureAlgorithm.HS512, environment.getProperty("token.secret"))
                .compact();
    }

}
