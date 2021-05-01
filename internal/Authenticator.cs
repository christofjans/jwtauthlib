using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtAuthLib
{
    public class Authenticator : IAuthenticator
    {
        public string Authenticate(LoginUser user, IUserAuthenticator userAuth, JwtConfig jwtConfig)
        {
            var authenticatedUser = userAuth.AuthenticateUser(user);

            return GenerateJwtBearerToken(jwtConfig, authenticatedUser);
        }

        private static string GenerateJwtBearerToken(JwtConfig jwtConfig, AuthenticatedUser? authenticatedUser)
        {
            if (authenticatedUser == null) throw new System.Exception("invalid login creds");

            var claims = new List<Claim>();
            claims.Add(new Claim("username", authenticatedUser.UserName));
            claims.Add(new Claim("displayname", authenticatedUser.DisplayName));

            // Add roles as multiple claims
            if (authenticatedUser.Roles != null)
            {
                foreach (var role in authenticatedUser.Roles)
                {
                    claims.Add(new Claim("role", role));
                }
            }

            var token = JwtHelper.GetJwtToken(
                authenticatedUser.UserName,
                jwtConfig.SigningKey,
                jwtConfig.Issuer,
                jwtConfig.Audience,
                TimeSpan.FromMinutes(jwtConfig.TokenTimeoutMinutes),
                claims.ToArray());

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<string> AuthenticateAsync(LoginUser user, IUserAuthenticator userAuth, JwtConfig jwtConfig)
        {
            var authenticatedUser = await userAuth.AuthenticateUserAsync(user);

            return GenerateJwtBearerToken(jwtConfig, authenticatedUser);
        }
    }
}