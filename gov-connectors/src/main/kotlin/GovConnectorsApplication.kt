package com.uk.gov.connectors

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import com.uk.gov.connectors.service.SyncService
import javax.annotation.PostConstruct

@SpringBootApplication
class GovConnectorsApplication(
    private val syncService: SyncService
) {

    @PostConstruct
    fun init() {
        syncService.subscribeToEvents()
    }

@Bean
fun webClient(): WebClient = WebClient.builder()
    .defaultHeader("Authorization", "Bearer secure-token") // Mock auth
    .build()

@Bean
fun webClient(): WebClient = WebClient.builder()
    .defaultHeader("Authorization", "Bearer secure-token") // Mock auth
    .build()

@Bean
fun webMvcConfigurer(): WebMvcConfigurer {
    return object : WebMvcConfigurer {
        override fun addCorsMappings(registry: CorsRegistry) {
            registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000", "http://localhost:3001")
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowCredentials(true)
        }
    }
}

fun main(args: Array<String>) {
    runApplication<GovConnectorsApplication>(*args)
}