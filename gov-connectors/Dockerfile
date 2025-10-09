FROM gradle:8.4-jdk17-alpine as builder
WORKDIR /app
COPY build.gradle.kts .
COPY src ./src
RUN gradle build --no-daemon

FROM openjdk:17-jre-slim
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar
CMD ["java", "-jar", "app.jar"]