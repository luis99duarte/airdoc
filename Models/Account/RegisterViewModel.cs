using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace identity.Models
{
    public class RegisterViewModel
    {

        [Required]
        public string Username { get; set; }
        [Required]
        public string Role { get; set; }
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
        [Required]
        public string Email { get; set; }
        public string ConfirmEmail { get; set; }

        public List<SelectListItem> Roles { get; }

        public string ReturnUrl { get; set; }

        public RegisterViewModel()
        {
        }
        public RegisterViewModel(List<SelectListItem> roles, string returnURL)
        {
            Roles = roles;
            ReturnUrl = returnURL;
        }


    }
}
