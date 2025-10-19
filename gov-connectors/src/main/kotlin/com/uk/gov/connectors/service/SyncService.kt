package com.uk.gov.connectors.service

import org.springframework.data.redis.core.ReactiveRedisTemplate
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import org.springframework.security.crypto.encrypt.Encryptors
import org.springframework.security.crypto.encrypt.TextEncryptor
import org.springframework.beans.factory.annotation.Value

@Service
class SyncService(
    private val redisTemplate: ReactiveRedisTemplate<String, String>,
    @Value("\${encryption.key:your-encryption-key}") private val encryptionKey: String,
    @Value("\${encryption.salt:your-salt}") private val salt: String
) {

    private val encryptor: TextEncryptor = Encryptors.text(encryptionKey, salt)

    fun publishEvent(eventType: String, data: Map<String, Any>): Mono<Long> {
        val event = mapOf(
            "type" to eventType,
            "data" to data,
            "timestamp" to System.currentTimeMillis()
        )
        val json = com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(event)
        return redisTemplate.convertAndSend("id-system-events", json)
    }

    fun encryptData(data: String): String {
        return encryptor.encrypt(data)
    }

    fun decryptData(encryptedData: String): String {
        return encryptor.decrypt(encryptedData)
    }

    fun cacheData(key: String, value: String, ttlSeconds: Long): Mono<Boolean> {
        return redisTemplate.opsForValue().set(key, value)
            .flatMap { success ->
                if (success && ttlSeconds > 0) {
                    redisTemplate.expire(key, java.time.Duration.ofSeconds(ttlSeconds))
                } else {
                    Mono.just(success)
                }
            }
    }

    fun getCachedData(key: String): Mono<String> {
        return redisTemplate.opsForValue().get(key)
    }

    fun subscribeToEvents() {
        redisTemplate.listenToChannel("id-system-events")
            .doOnNext { message ->
                val event = com.fasterxml.jackson.databind.ObjectMapper().readValue(message.message, Map::class.java)
                when (event["type"]) {
                    "identity_verified" -> {
                        // Could update government records if API allows
                        println("Identity verified event: $event")
                    }
                    "user_registered" -> {
                        // Sync new user to government systems
                        println("User registered event: $event")
                    }
                }
            }
            .subscribe()
    }
}