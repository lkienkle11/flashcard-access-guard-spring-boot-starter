package com.microservices.guard;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.microservices.dto.common.SetCheckingParam;
import com.microservices.entity.TempSetCard;
import com.microservices.guard.port.SetFlashcardReader;
import com.microservices.utils.ReactiveRedisUtils;
import com.microservices.utils.RedisUtils;
import io.vavr.control.Option;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = lombok.AccessLevel.PRIVATE, makeFinal = true)
public class DefaultSetAccessGuard implements SetAccessGuard {
    SetFlashcardReader reader;
    CacheManager cacheManager;
    GuardProperties props;

    ReactiveRedisUtils reactiveRedis;

    RedisUtils redisUtils;

    PasswordEncoder encoder = new BCryptPasswordEncoder();

    @NonFinal
    @Value("#{setPassInfoCacheName}")
    String setPassInfoCacheName;

    @NonFinal
    @Value("#{validateSetsName}")
    String validatedSetsName;

    private static final String SET_FORMAT_KEY = "set:%s:pass_checked";

    private static final String SET_FORMAT_KEY_REDIS = "set:%s:pass_checked:user:%s";

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> setCardInfoCache() {
        return (Cache<Object, Object>)
                Objects.requireNonNull(cacheManager.getCache(setPassInfoCacheName)).getNativeCache();
    }

    @SuppressWarnings("unchecked")
    private Cache<Object, Object> validatedSetCardCache() {
        return (Cache<Object, Object>)
                Objects.requireNonNull(cacheManager.getCache(validatedSetsName)).getNativeCache();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Mono<Void> checkReactive(SetCheckingParam param) {
        if (reactiveRedis == null) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Reactive Redis is not configured"
            ));
        }

        String userId = param.getUserId();
        String formatKey = String.format(SET_FORMAT_KEY, param.getSetId());
        String formatKeyRedis = String.format(SET_FORMAT_KEY_REDIS, param.getSetId(), userId);


        Mono<TempSetCard> setCardInfo = Mono.defer(() -> {
            Object checkL1Set = setCardInfoCache().getIfPresent(param.getSetId());
            if (checkL1Set != null) {
                Option<TempSetCard> optSet = (Option<TempSetCard>) checkL1Set;
                if (optSet.isDefined()) {
                    return Mono.just(optSet.get());
                } else {
                    throw new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Set not found in cache: " + param.getSetId()
                    );
                }
            }

            return reader.findReactive(param.getSetId())
                    .switchIfEmpty(Mono.error(new ResponseStatusException(
                            HttpStatus.NOT_FOUND, "Set not found: " + param.getSetId()
                    )))
                    .flatMap(Mono::just)
                    .doOnNext(set -> setCardInfoCache().put(param.getSetId(), Option.of(set)))
                    .doOnError(e -> {
                        if (e instanceof ResponseStatusException empty &&
                                empty.getStatusCode() == HttpStatus.NOT_FOUND) {
                            setCardInfoCache().put(param.getSetId(), Option.<TempSetCard>none());
                        }
                    });
        });

        return setCardInfo
                .publishOn(Schedulers.boundedElastic())
                .flatMap(set -> {
                    if (isUnprotected(set) || isOwner(param.getUserId(), param.getAuthorizes(), set)) {
                        return Mono.empty();
                    }

                    Cache<Object, Object> l1CacheValidate = (Cache<Object, Object>)
                            setCardInfoCache().getIfPresent(formatKey);

                    if (l1CacheValidate == null) {
                        l1CacheValidate = Caffeine.newBuilder()
                                .maximumSize(500)
                                .build();
                    }

                    Long timeSet = (Long) l1CacheValidate.getIfPresent(userId);
                    if (timeSet != null) {
                        long currentTime = System.currentTimeMillis();
                        if (currentTime < timeSet) {
                            return Mono.empty();
                        }
                    }

                    Cache<Object, Object> finalL1CacheValidate = l1CacheValidate;
                    String rawPwd = param.getRawPwd();
                    String rawValidAt = param.getRawValidAt();

                    return reactiveRedis
                            .hasKey(formatKeyRedis)
                            .flatMap(isMember -> {
                                if (Boolean.TRUE.equals(isMember)) {
                                    return reactiveRedis
                                            .getFromRedis(formatKeyRedis, Long.class)
                                            .map(expiredAt -> {
                                                finalL1CacheValidate.put(userId, expiredAt);
                                                validatedSetCardCache().put(formatKey, finalL1CacheValidate);
                                                return Mono.empty();
                                            })
                                            .then();
                                }

                                // 4) xác thực password
                                if (rawPwd == null || rawPwd.isBlank()
                                        || !encoder.matches(rawPwd, set.hashPassword())) {
                                    return Mono.error(new ResponseStatusException(
                                            HttpStatus.FORBIDDEN, "{\"type\":\"Password\"}"
                                    ));
                                }
                                // 5) parse TTL và lưu vào Redis set
                                long ttl = parseValidAt(rawValidAt);
                                long now = System.currentTimeMillis();
                                return reactiveRedis
                                        .saveToSet(formatKeyRedis, now + ttl,
                                                ttl, TimeUnit.SECONDS)           // :contentReference[oaicite:1]{index=1}
                                        .doOnNext(v -> finalL1CacheValidate.put(userId, now + ttl))
                                        .doOnNext(v -> validatedSetCardCache().put(formatKey, finalL1CacheValidate))
                                        .then();
                            });
                }).then();
    }

    @Override
    @SuppressWarnings("unchecked")
    public void checkBlocking(SetCheckingParam param) {
        if (redisUtils == null) {
            throw new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Blocking Redis is not configured"
            );
        }

        String userId = param.getUserId();
        String formatKey = String.format(SET_FORMAT_KEY, param.getSetId());
        String formatKeyRedis = String.format(SET_FORMAT_KEY_REDIS, param.getSetId(), userId);

        Option<TempSetCard> optSet = (Option<TempSetCard>)
                setCardInfoCache().getIfPresent(param.getSetId());
        TempSetCard set = null;

        if (optSet != null) {
            if (optSet.isDefined()) {
                set = optSet.get();
            } else {
                throw new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Set not found in cache: " + param.getSetId()
                );
            }
        }

        if (set == null) {
            set = reader.findBlocking(param.getSetId());
            if (set == null) {
                optSet = Option.none();
                setCardInfoCache().put(param.getSetId(), optSet);
                throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Set not found: " + param.getSetId());
            }
            setCardInfoCache().put(param.getSetId(), Option.of(set));
        }

        if (isUnprotected(set) || isOwner(param.getUserId(), param.getAuthorizes(), set)) {
            return;
        }

        Cache<Object, Object> l1CacheValidate = (Cache<Object, Object>)
                setCardInfoCache().getIfPresent(formatKey);

        if (l1CacheValidate == null) {
            l1CacheValidate = Caffeine.newBuilder()
                    .maximumSize(500)
                    .build();
        }

        Long timeSet = (Long) l1CacheValidate.getIfPresent(userId);

        if (timeSet != null) {
            long currentTime = System.currentTimeMillis();
            if (currentTime < timeSet) {
                return;
            }
        }

        String rawPwd = param.getRawPwd();
        String rawValidAt = param.getRawValidAt();

        Boolean isMember = redisUtils.isMember(formatKeyRedis, Long.class);
        if (Boolean.TRUE.equals(isMember)) {
            Long expiredAt = redisUtils.getFromRedis(formatKeyRedis, Long.class);
            l1CacheValidate.put(userId, expiredAt);
            validatedSetCardCache().put(formatKey, l1CacheValidate);
            return;
        }

        // 4) xác thực password
        if (rawPwd == null || rawPwd.isBlank()
                || !encoder.matches(rawPwd, set.hashPassword())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "{\"type\":\"Password\"}");
        }
        // 5) parse TTL và lưu vào Redis set
        long ttl = parseValidAt(rawValidAt);
        long now = System.currentTimeMillis();
        redisUtils.saveToSet(formatKeyRedis, now + ttl, ttl, TimeUnit.SECONDS);
        l1CacheValidate.put(userId, now + ttl);
        validatedSetCardCache().put(formatKey, l1CacheValidate);
    }

    private boolean isUnprotected(TempSetCard set) {
        String hash = set.hashPassword();
        return hash == null || hash.isBlank();
    }

    private boolean isOwner(String userId, List<String> up, TempSetCard set) {
        boolean isAdmin = up.stream()
                .anyMatch(a -> a.equals("ROLE_ADMIN") || a.equals("ADMIN"));
        return isAdmin || userId.equals(set.appUserId().toString());
    }

    private long parseValidAt(String raw) {
        long max = 7 * 24 * 3600L;
        if (raw == null) return max;
        try {
            long v = Long.parseLong(raw);
            if (v < 0 || v > max) throw new NumberFormatException();
            return v;
        } catch (NumberFormatException ex) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "{\"type\":\"Valid at\",\"reason\":\"Invalid range\"}"
            );
        }
    }
}
