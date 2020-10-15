using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebApi.Controllers
{
    public class HomeController : Controller
    {
        public string Index()
        {
            ViewBag.Title = "Home Page";

            //return View();
            return "try /api/values/thumbprint";
        }
    }
}
