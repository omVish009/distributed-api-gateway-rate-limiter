package com.example.gateway;

import java.time.Instant;
import java.util.List;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Mono;

@Service
public class RedisRateLimiterService {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final RedisScript<List> tokenBucketScript;

    public RedisRateLimiterService(ReactiveStringRedisTemplate redisTemplate,
                                   RedisScript<List> tokenBucketScript) {
        this.redisTemplate = redisTemplate;
        this.tokenBucketScript = tokenBucketScript;
    }

    public Mono<RateLimitDecision> check(ClientContext context, AdaptivePolicy policy) {
        String key = "rate_limit:" + context.clientId() + ":" + context.path();
        long now = Instant.now().getEpochSecond();

        List<String> keys = List.of(key);
        List<String> args = List.of(
                String.valueOf(policy.capacity()),
                String.valueOf(policy.refillRate()),
                String.valueOf(now),
                "1"
        );

        return redisTemplate.execute(tokenBucketScript, keys, args)
                .next()
                .map(result -> {
                    boolean allowed = Long.parseLong(result.get(0).toString()) == 1;
                    long remainingTokens = Long.parseLong(result.get(1).toString());
                    long retryAfterSeconds = Long.parseLong(result.get(2).toString());

                    String reason = allowed ? "Allowed" : "Rate limit exceeded";

                    return new RateLimitDecision(
                            allowed,
                            remainingTokens,
                            retryAfterSeconds,
                            reason
                    );
                });
    }
}