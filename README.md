# JwtAuthLib

------------

JwtAuthLib is a .NET library to help implement authentication for WebApi projects without using .Net Core identity. As the name implies it uses Jwt bearer tokens.

The implementation of this library relies heavily on [this blog post by Rick Strahl](https://weblog.west-wind.com/posts/2021/Mar/09/Role-based-JWT-Tokens-in-ASPNET-Core) (and blatantly steals some code; thanks Rick 😉).

## Interfaces

There are 2 main interfaces:

* `IUserAuthenticator` : this is an interface that *you* implement. It accepts a username and password and returns the authenticated user object.
* `IAuthenticator` : the implementation is provided by JwtAuthLib (`JwtAuthLib.Authenticator`). It accepts a username/password, an `IUserAuthenticator` interface and a `JwtConfig` object. It returns the Jwt bearer token.


## JwtConfig

The most important property of `JwtConfig` is `SigningKey` (all other properties can be left at their default values). **The signing key must be kept secret.** If an attacker got a hold of your signing key they could create Jwt tokens and gain access to your site.

## Setup

In `StartUp.cs` add the following code in `ConfigureServices` :

```cs
using JwtAuthLib;

services.AddJwtAuth(jwtConfig);
```

You would typically get the jwtConfig from `Configuration`.

In `Configure` you need to add :

```cs
app.UseAuthentication();
app.UseAuthorization();
```

These calls need to be added *after* routing and *before* endpoint setup.

## Logging in

In your login controller you need to add the following code :

```cs
private readonly IUserAuthenticator userAuthenticator;
private readonly IAuthenticator authenticator;

[AllowAnonymous]
[HttpPost]
[Route("authenticate")]        
public string Authenticate(LoginUser loginUser)
{
    return authenticator.Authenticate(loginUser, userAuthenticator, jwtConfig);
}
```

`userAuthenticator` is an instance of `IUserAuthenticator` . This is an implementation that *you* provide to authenticate a username/password. Typically, your implementation would check a database (make sure you don't store passwords in cleartext; properly salting and hashing of passwords is outside the scope of JwtAuthLib).

`authenticator` is an instance of `IAuthenticator`. This was set up with DI in `ConfigureServices`.

The `jwtConfig` object must be an object with the *same property values* as the one you passed in to `services.AddJwtAuth` in `ConfigureServices`.

## Client

Once you have retrieved the Jwt bearer token (by calling the Authenticate method of your login controller) you use it by adding the following header to all you Http calls:

```http
Authorization: Bearer <YourJwtBearerToken>
```

Example :

```http
GET http://acme.com/getmessage
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjaHJpc3RvZiIsImp0aSI6ImRjNjcyNTExLWEyYWYtNDJmNi1hZGVkLTVlN2VmZjE0NTI0NyIsInVzZXJuYW1lIjoiY2hyaXN0b2YiLCJkaXNwbGF5bmFtZSI6ImNocmlzdG9mIiwicm9sZSI6WyJhZG1pbiIsInJvbGUxIl0sImV4cCI6MTYxODc4OTgxMywiaXNzIjoiaHR0cHM6Ly9teXNpdGUuY29tIiwiYXVkIjoiaHR0cHM6Ly9teXNpdGUuY29tIn0.hkHJWUuDUbqH3WKf-N24Bj9JZpcNSi__PQKVFlhbwaI
```

Don't forget the word `Bearer` before your token. 