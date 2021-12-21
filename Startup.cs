using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Mvc;
using identity.Data;
using IdentityServer4.Models;
using NETCore.MailKit.Extensions;
using NETCore.MailKit.Infrastructure.Internal;

namespace identity
{
    public class Startup
    {

        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            Environment = env;


        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }


        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            /*
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();
            services.AddControllersWithViews();
            services.AddRazorPages();*/

            if (Environment.IsDevelopment())
                services.AddDbContext<ApplicationDbConatext>(options =>
                {
                    // options.UseSqlServer(Configuration.GetConnectionString("localSQL"));
                    options.UseMySql(Configuration.GetConnectionString("AUTHSERVERSQL"));
                });
            else

                services.AddDbContext<ApplicationDbConatext>(options =>
                {
                    options.UseMySql(Configuration.GetConnectionString("AUTHSERVERSQL"));
                });

            services.AddIdentity<ApplicationUser, IdentityRole>(op =>
            {
                op.Password.RequireDigit = true;
                op.Password.RequiredLength = 6;
                op.Password.RequireLowercase = true;
                op.Password.RequireUppercase = true;
                op.Password.RequireNonAlphanumeric = false;
                op.User.RequireUniqueEmail = true;

                op.SignIn.RequireConfirmedEmail = true;
            })
                .AddEntityFrameworkStores<ApplicationDbConatext>()
                .AddDefaultTokenProviders(); 

            /*services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbConatext>()
                .AddDefaultTokenProviders();*/
           
            // Add application services.
            //  services.AddTransient<IEmailSender, EmailSender>();

            services.AddMvc(op => { op.EnableEndpointRouting = false; });

            // configure identity server with in-memory stores, keys, clients and scopes
            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryPersistedGrants()
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddInMemoryApiResources(Config.GetApis())
                .AddInMemoryClients(Config.GetClients())
                .AddAspNetIdentity<ApplicationUser>();

            /*
             * Email Configuration 
             */

            /*
            var emailConfig = Configuration
                .GetSection("EmailConfiguration")
                .Get<EmailConfiguration>();

            services.AddSingleton(emailConfig);
            services.AddScoped<IEmailSender, EmailSender>(); */

            // MailKit send emails
            services.AddMailKit(config => config.UseMailKit(Configuration.GetSection("Email").Get<MailKitOptions>()));

        }


  


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IServiceProvider serviceProvider)
        {

            //Inits.CreateRoles(serviceProvider).Wait();

            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                //app.UseHsts();
            }
            //app.UseHttpsRedirection();
            app.UseStaticFiles();

            //   app.UseRouting();

            //  app.UseAuthentication();
            //    app.UseAuthorization();
            app.UseIdentityServer();
            /*
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });*/
            app.UseMvc(routes =>
            {
               /* routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");*/
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Account}/{action=Login}/{id?}");
            });
        }
    }
}
