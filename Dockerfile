# Use an official Java runtime as the base image
FROM openjdk:11-jre-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the jar file into the container at /app
# Assuming the JAR file is named 'my-java-app.jar' and is in the target directory
COPY target/signcheck-1.0.0-SNAPSHOT.jar /app/signcheck-1.0.0-SNAPSHOT.jar
COPY /keystore.p12 /app/keystore.p12
COPY /config.cfg /app/config.cfg
EXPOSE 8081
# Specify the command to run when the container starts
CMD ["java", "-jar", "/app/signcheck-1.0.0-SNAPSHOT.jar"]
