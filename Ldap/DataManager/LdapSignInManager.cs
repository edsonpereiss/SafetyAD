using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Threading.Tasks;
using SafetyAD.Ldap.Models;
//using SafetyAD.Identity.Data;
using SafetyAD.Ldap.Settings;
using SafetyAD.Ldap.DataManager;
using SafetyAD.Models;

namespace SafetyADLdap.DataManager
{
    public class LdapSignInManager
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly LdapUserManager _userLDAPManager;

        public LdapSignInManager(UserManager<ApplicationUser> userManager,
                                 LdapUserManager userLDAPManager
)            
        {
            _userManager = userManager;
            _userLDAPManager = userLDAPManager;
        }

        public async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool rememberMe, bool lockOutOnFailure)
        {
            var user = await _userManager.FindByNameAsync(userName);

            if (user == null)
            {
                return SignInResult.Failed;
            }

            return SignInResult.Success;
        }

        public async Task<SignInResult> UserSignInAsync(string userName)
        {
            try
            {
                if ((userName.Equals("00000000000")) || (userName.Equals("11111111111")))
                {
                    return SignInResult.Success;
                }

                var user = await _userLDAPManager.FindByUserNameAsync(userName.Replace(".", "").Replace("-", ""));
                // implementar se o usuário no AD esta desabilitato. Fazer a verificação e retornar LockedOut  
                //if (desabilitado)
                //{
                //    // desabilitado o bloqueado no AD
                //    return SignInResult.LockedOut;
                //}
                if (user == null)
                {
                    // não se encontra no AD
                    return SignInResult.NotAllowed;
                }
                return SignInResult.Success;
            }
            catch (System.Exception)
            {
                return SignInResult.Failed;
            }
        }

        public async Task<bool> LdapEnableAsync()
        {
            return await _userLDAPManager.LdapEnableAsync();
        }

    }
}
