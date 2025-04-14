package com.fourirbnb.gateway.application.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class GatewayJwtAuthenticationFilter implements GlobalFilter, Ordered {

  @Value("${security.jwt.secret}")
  private String jwtSecret;

  private final WhitelistProperties whitelistProperties;

  public GatewayJwtAuthenticationFilter(WhitelistProperties whitelistProperties) {
    this.whitelistProperties = whitelistProperties;
  }

  //whiteList
  private boolean isWhitelisted(String path) {
    return whitelistProperties.getPaths().stream().anyMatch(path::startsWith);
  }

  // jwt token 검사
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    log.info(jwtSecret);
    ServerHttpRequest request = exchange.getRequest();
    String path = request.getPath().value();
    log.info("path: {}", path);
    // whitelisted 통과
    if (isWhitelisted(path)) {
      return chain.filter(exchange);
    }
    String token = extractToken(exchange);
    Claims claims = extractClaims(token);
    log.info("claims: {}", claims);
    //token 만료 or 변조
    if (token == null || claims == null) {
      //401
      return unauthorizedResponse(exchange);
    }
    //token 변조
    String userId = claims.get("userId", String.class);
    String role = claims.get("role", String.class);
    log.info("userId: {}, role: {}", userId, role);
    if (userId == null || role == null) {
      //401
      return unauthorizedResponse(exchange);
    }

    ServerHttpRequest mutatedRequest = request.mutate()
        .header("Authorization", "Bearer " + token)
        .header("X-User-Id", userId)
        .header("X-User-Role", role)
        .build();
    log.info("mutatedRequest: {}", mutatedRequest);
    //헤더 추가후 넘김
    return chain.filter(exchange.mutate().request(mutatedRequest).build());
  }

  //토큰
  private String extractToken(ServerWebExchange exchange) {
    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      return authHeader.substring(7);
    }
    return null;
  }

  private Claims extractClaims(String token) {
    // BASE64 디코딩 후 HMAC 변환
    try {
      SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
      Claims claims = Jwts.parser()
          .verifyWith(key)
          .build()
          .parseEncryptedClaims(token)
          .getPayload();

      //만료시간 확인
      Date expiration = claims.getExpiration();
      if (expiration != null && expiration.before(new Date())) {
        return null;
      }
      return claims;
    } catch (Exception e) {
      log.error(e.getMessage());
      return null;
    }
  }

  //토큰만료 401
  private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
  }

  //실행순서 최우선
  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }
}
