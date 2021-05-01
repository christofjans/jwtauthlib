using System.Collections.Generic;
using System.Threading.Tasks;

namespace JwtAuthLib
{
    public class LoginUser
    {
        public string UserName {get;set;} = "";
        public string Password {get;set;} = "";
    }

    public class AuthenticatedUser
    {
        public string UserName {get;set;} = "";
        public string DisplayName {get;set;} = "";
        public List<string>? Roles {get;set;}
    }

    public class JwtConfig
    {
        public string Audience {get;set;} = "http://mysite.com";
        public string Issuer {get;set;} = "http://mysite.com";
        public string SigningKey {get;set;} = "";
        public int TokenTimeoutMinutes {get;set;} = 10;
    }

    public interface IAuthenticator
    {
        string Authenticate(LoginUser user, IUserAuthenticator userAuth, JwtConfig jwtConfig);
        Task<string> AuthenticateAsync(LoginUser user, IUserAuthenticator userAuth, JwtConfig jwtConfig);
    }

    public interface IUserAuthenticator
    {
        /// If authenticated, returns an AuthenticatedUser instance, otherwise it returns null.
        AuthenticatedUser? AuthenticateUser(LoginUser loginUser);

        Task<AuthenticatedUser?> AuthenticateUserAsync(LoginUser loginUser);
    }
}