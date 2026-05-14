package com.example.gateway;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.script.RedisScript;

@Configuration
public class RedisScriptConfig {

    @Bean
    public RedisScript<List> tokenBucketScript() {
        return RedisScript.of(
                new ClassPathResource("token_bucket.lua"),
                List.class
        );
    }
}