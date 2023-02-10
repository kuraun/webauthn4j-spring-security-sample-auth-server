# WebAuthn4J Spring Security Authorization Server Sample

WebAuthn4J Spring Security Authorization Server Sample is a based on [MPA sample application for WebAuthn4J Spring Security](https://github.com/webauthn4j/webauthn4j-spring-security/tree/master/samples/mpa).

## Disclaimer

<b>WARNING: Do not use this project in a production environment. It's just a sample application to test OAuth2 login.</b>    
Currently, most implementations of `Authorization Server` included in [spring-security-oauth2](https://spring.io/projects/spring-security-oauth) are deprecated.
This project contains deprecated implementations.  
Spring Community is actively developing [the Spring Authorization Server](https://spring.io/blog/2020/04/15/announcing-the-spring-authorization-server).
In the near future, existing Authorization Server implementations will replace this new version of the framework.

## Acknowledgments

For the implementation of this project, I referred to the following project. I would like to express my gratitude here.

- [WebAuthn4J Spring Security Samples](https://github.com/webauthn4j/webauthn4j-spring-security/tree/master/samples)
- [Spring Security OAuth 2.4 Migration Sample](https://github.com/jgrandja/spring-security-oauth-2-4-migrate)

## Build

This project uses a Gradle based build system.
In the instructions below, `gradlew` is invoked from the root of the source tree and serves as a cross-platform,
self-contained bootstrap mechanism for the build.

### Prerequisites

- Java8 or later
- Spring Framework 5.0 or later

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

#### Signup

http://localhost:8080/signup  
Enter the username and password to register the authenticator.

#### Login

Please return to the sign-up page and press `OAuth2 Login` link.  
When you are redirected to the login page, press `Fast Login` button to authenticate with the authenticator.  
<b>WARNING: It may not work if a security extension is installed in your browser</b>.  

You will be taken to the default Approval page of Legacy Spring Security, so select Approve and press the `Authorize` button.
You will be able to get an authorization code.

#### Access Token Request

Get an access token using the issued authorization code.  
The following is an example of an access token request using cURL. Set the authorization code in `{code}`.

```shell
curl --location --request POST 'http://localhost:8080/oauth/token' \
--header 'Authorization: Basic b2F1dGgyLWNsaWVudDpzZWNyZXQ=' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'code={code}' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'redirect_uri=http://localhost:8080/authorized/callback' \
--data-urlencode 'state=test'
```

## License

WebAuthn4J Spring Security is Open Source software released under the
[Apache 2.0 license](http://www.apache.org/licenses/LICENSE-2.0.html).
