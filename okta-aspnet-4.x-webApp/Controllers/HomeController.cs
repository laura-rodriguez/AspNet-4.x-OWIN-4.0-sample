using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

namespace okta_aspnet_4.x_webApp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var claim = HttpContext.GetOwinContext().Authentication.User.FindFirst("name");
            ViewBag.Username = (claim != null) ? claim.Value : string.Empty;

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}