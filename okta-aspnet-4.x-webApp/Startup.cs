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

[assembly: OwinStartup(typeof(okta_aspnet_4.x_webApp.Startup))]

namespace okta_aspnet_4.x_webApp
{
    public class Startup
    {
        string clientId = ConfigurationManager.AppSettings["ClientId"];
        string redirectUrl = ConfigurationManager.AppSettings["redirectUrl"];
        string authority = ConfigurationManager.AppSettings["Authority"];
        string clientSecret = ConfigurationManager.AppSettings["ClientSecret"];

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
                    // Sets the ClientId, authority, RedirectUri as obtained from web.config
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Authority = authority,
                    RedirectUri = redirectUrl,
                    PostLogoutRedirectUri = redirectUrl,
                    ResponseType = OpenIdConnectResponseType.Code,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = this.OnAuthenticationFailed
                    }
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
