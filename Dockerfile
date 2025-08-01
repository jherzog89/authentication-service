# Stage 1: Build the application
FROM maven:3.9.9-eclipse-temurin-24 AS builder

WORKDIR /app
COPY pom.xml /app/
COPY src /app/src
RUN mvn clean package

# Stage 2: Create runtime image
FROM eclipse-temurin:24-jre

WORKDIR /app
COPY --from=builder /app/target/authentication-service-0.0.1-SNAPSHOT.jar /app/app.jar

EXPOSE 8777
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

#BUILD
#docker build -t jherzog89/authentication-service:v1 .

#RUN in same network
#docker network create my-app-network
#docker run --name authentication-container --network my-app-network -p 8777:8777 jherzog89/authentication-service:v1