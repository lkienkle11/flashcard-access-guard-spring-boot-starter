package com.microservices.guard;

import com.microservices.dto.common.SetCheckingParam;
import com.microservices.dto.security.UserPrincipal;
import reactor.core.publisher.Mono;

public interface SetAccessGuard {
    Mono<Void> checkReactive(SetCheckingParam param);

    void checkBlocking(SetCheckingParam param);
}
