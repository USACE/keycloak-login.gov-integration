FROM jboss/keycloak:11.0.2
COPY target/login_gov-11.0.2-SNAPSHOT.jar /opt/jboss/keycloak/standalone/deployments/
RUN touch /opt/jboss/keycloak/standalone/deployments/login_gov-11.0.2-SNAPSHOT.jar.dodeploy


