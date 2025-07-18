package com.microservices.config;

import com.microservices.guard.GuardProperties;
import com.microservices.guard.SetAccessGuard;
import com.microservices.guard.port.SetFlashcardReader;
import com.microservices.utils.ReactiveRedisUtils;
import com.microservices.utils.RedisUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(GuardProperties.class)
public class GuardAutoConfiguration {
    private static final String SET_PASS_INFO_CACHE_NAME = "setPassInfo";
    private static final String VALIDATE_SETS_NAME = "validatedSets";

    @Bean("setPassInfoCacheName")
    public String getSetPassInfoCacheName() {
        return SET_PASS_INFO_CACHE_NAME;
    }

    @Bean("validateSetsName")
    public String getValidateSetsName() {
        return VALIDATE_SETS_NAME;
    }

    @Bean
    public SetAccessGuard setAccessGuard(
            CacheManager cacheManager,
            GuardProperties props,
            ObjectProvider<SetFlashcardReader> reader,
            ObjectProvider<ReactiveRedisUtils> reactiveRedis,
            ObjectProvider<RedisUtils> redisUtilsProvider) {
        if (reader.getIfAvailable() == null) {
            throw new IllegalStateException("SetFlashcardReader bean is required for SetAccessGuard");
        }
        return new com.microservices.guard.DefaultSetAccessGuard(
                reader.getIfAvailable(),
                cacheManager,
                props,
                reactiveRedis.getIfAvailable(),
                redisUtilsProvider.getIfAvailable()
        );
    }
}
