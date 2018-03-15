using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.Linq;
using IdentityModel.Client;
using System.Security.Claims;

[assembly: OwinStartup(typeof(okta_aspnet_4.x_webApp.Startup))]

namespace okta_aspnet_4.x_webApp
{
    public class Startup
    {
        string clientId = ConfigurationManager.AppSettings["okta:ClientId"];
        string redirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"];
        string authority = ConfigurationManager.AppSettings["okta:Authority"];
        string clientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"];
        string postLogoutRedirectUri = ConfigurationManager.AppSettings["okta:PostLogoutRedirectUri"];

        /// <summary>
        /// Configure OWIN to use OpenIdConnect 
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Authority = authority,
                    RedirectUri = redirectUri,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    PostLogoutRedirectUri = postLogoutRedirectUri,

                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = this.OnAuthenticationFailed,

                        SecurityTokenValidated = n =>
                        {
                            var tokenId = n.ProtocolMessage.IdToken;

                            if (tokenId != null)
                            {
                                n.AuthenticationTicket.Identity.AddClaim(new Claim("id_token", tokenId));
                            }

                            return Task.FromResult(0);
                        },

                        RedirectToIdentityProvider = n =>
                        {
                            // if signing out, add the id_token_hint
                            if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                            {
                                var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                                if (idTokenHint != null)
                                {
                                    n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                }

                            }

                            return Task.FromResult(0);
                        }
                    },                    
                }
            );
        }

        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
    }
}
