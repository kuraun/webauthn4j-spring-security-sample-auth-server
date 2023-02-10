# WebAuthn4J Spring Security Authorization Server Sample

WebAuthn4J Spring Security Authorization Server Sample is a based on [MPA sample application for WebAuthn4J Spring Security](https://github.com/webauthn4j/webauthn4j-spring-security/tree/master/samples/mpa).

## Disclaimer

<b>WARNING: Do not use this project in a production environment. It's just a sample application to test OAuth2 login.</b>    
This sample using [spring-authorization-server](https://github.com/spring-projects/spring-authorization-server).

## Acknowledgments

The following projects were used as references for the implementation of this project. I would like to express my gratitude here.  
Also, since this project is based on Spring6, it includes a project that updates webauthn4j-spring-security-core.

- [WebAuthn4J Spring Security](https://github.com/webauthn4j/webauthn4j-spring-security/)

## Build

This project uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java17
- Spring Framework 6.0 or later

### Checkout sources

```bash
git clone https://github.com/kuraun/webauthn4j-spring-security-sample-auth-server
```

### Build all jars

```bash
./gradlew build
```

### Execute sample application

```bash
./gradlew bootRun
```

## License

WebAuthn4J Spring Security is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
