using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using AuthenticationProject.Models;

namespace AuthenticationProject.Controllers
{
    
    public class AccessController : Controller
    {
        public IActionResult Login()
        {
            ClaimsPrincipal claimuser = HttpContext.User;
            if (claimuser.Identity.IsAuthenticated)
                return RedirectToAction("Index","Home");
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginCredentials LogCred)
        {
            if (LogCred.Email=="ezhilkannan1996@gmail.com" && LogCred.Password=="123")
            {
                List<Claim> claims = new List<Claim>() 
                { 
                new Claim(ClaimTypes.NameIdentifier,LogCred.Email),
                new Claim("OtherProperties","Example Role")
                };
                ClaimsIdentity identity = new ClaimsIdentity(claims,CookieAuthenticationDefaults.AuthenticationScheme);
                AuthenticationProperties properties= new AuthenticationProperties() 
                {
                AllowRefresh = true,
                IsPersistent = LogCred.KeepLoggedIn
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity), properties);
                return RedirectToAction("Index", "Home");
            }
            ViewData["ValidateMessage"] = "User not found";
            return View();
        }

      
        public async Task<IActionResult> Logout()
        {
             await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login","Access");
        }
    }
}
