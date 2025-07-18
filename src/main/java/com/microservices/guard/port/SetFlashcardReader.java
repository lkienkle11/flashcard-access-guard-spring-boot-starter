package com.microservices.guard.port;

import com.microservices.entity.TempSetCard;
import org.springframework.lang.Nullable;
import reactor.core.publisher.Mono;

public interface SetFlashcardReader {
    Mono<TempSetCard> findReactive(Object userId);     // Reactive service dùng

    @Nullable
    TempSetCard findBlocking(Object userId); // MVC dùng
}
