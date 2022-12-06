﻿namespace AuthenticationProject.Models
{
    public class LoginCredentials
    {
        public string Email { get; set; }
        public string Password { get; set; }

        public bool KeepLoggedIn { get; set; }
    }
}
