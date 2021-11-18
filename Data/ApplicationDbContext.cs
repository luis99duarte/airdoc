using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace identity.Data
{
    public class ApplicationDbConatext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbConatext(DbContextOptions<ApplicationDbConatext> options)
            : base(options)
        {
        }
    }
}
