package com.example.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class RateLimiterFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterFilter.class);

    private final ClientContextExtractor contextExtractor;
    private final AdaptivePolicyEngine adaptivePolicyEngine;
    private final RedisRateLimiterService redisRateLimiterService;
    private final ObjectMapper objectMapper;

    public RateLimiterFilter(ClientContextExtractor contextExtractor,
                             AdaptivePolicyEngine adaptivePolicyEngine,
                             RedisRateLimiterService redisRateLimiterService,
                             ObjectMapper objectMapper) {
        this.contextExtractor = contextExtractor;
        this.adaptivePolicyEngine = adaptivePolicyEngine;
        this.redisRateLimiterService = redisRateLimiterService;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ClientContext context = contextExtractor.extract(exchange);
        AdaptivePolicy policy = adaptivePolicyEngine.resolvePolicy(context);

        return redisRateLimiterService.check(context, policy)
                .flatMap(decision -> {
                    if (decision.allowed()) {
                        exchange.getResponse().getHeaders().add("X-RateLimit-Remaining", String.valueOf(decision.remainingTokens()));
                        exchange.getResponse().getHeaders().add("X-RateLimit-Policy", policy.reason());
                        log.info("ALLOW clientId={} ip={} path={} reason={} remaining={}",
                                context.clientId(), context.ip(), context.path(), decision.reason(), decision.remainingTokens());
                        return chain.filter(exchange);
                    }

                    log.warn("BLOCK clientId={} ip={} path={} reason={} retryAfter={}",
                            context.clientId(), context.ip(), context.path(), decision.reason(), decision.retryAfterSeconds());
                    return write429(exchange, decision, context);
                });
    }

    private Mono<Void> write429(ServerWebExchange exchange,
                                RateLimitDecision decision,
                                ClientContext context) {
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().add("Retry-After", String.valueOf(decision.retryAfterSeconds()));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Too Many Requests");
        body.put("reason", decision.reason());
        body.put("clientId", context.clientId());
        body.put("path", context.path());
        body.put("retryAfterSeconds", decision.retryAfterSeconds());
        body.put("remainingTokens", decision.remainingTokens());

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (JsonProcessingException e) {
            bytes = "{\"message\":\"Too Many Requests\"}".getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}