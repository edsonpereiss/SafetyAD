using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SafetyAD.Ldap.Models;
using SafetyAD.Ldap.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SafetyAD.Ldap.DataManager
{
    public class LdapUserManager
    {
        private readonly ILdapService _ldapService;

        public LdapUserManager( ILdapService ldapService)
        {
            this._ldapService = ldapService;
        }

        public LdapUser GetAdministrator()
        {
            return this._ldapService.GetAdministrator();
        }

        /// <summary>
        /// Checks the given password agains the configured LDAP server.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public  Task<bool> CheckPasswordAsync(LdapUser user, string password)
        {
            return Task.FromResult(this._ldapService.Authenticate(user.DistinguishedName, password));
        }

        public  Task<bool> HasPasswordAsync(LdapUser user)
        {
            return Task.FromResult(true);
        }

        public  Task<LdapUser> FindByIdAsync(string userId)
        {
            return Task.FromResult(this._ldapService.GetUserByUserNameFirst(userId));
        }

        public  Task<LdapUser> FindByUserNameAsync(string userName)
        {
            return Task.FromResult(this._ldapService.GetUserByUserName(userName));
        }

        public  async Task<IdentityResult> CreateAsync(LdapUser user, string password)
        {
            try
            {
                this._ldapService.AddUser(user, password);
            }
            catch (Exception e)
            {
                return await Task.FromResult(IdentityResult.Failed(new IdentityError() { Code = "LdapUserCreateFailed", Description = e.Message ?? "The user could not be created." }));
            }

            return await Task.FromResult(IdentityResult.Success);
        }

        public async Task<IdentityResult> DeleteUserAsync(string distinguishedName)
        {
            try
            {
                this._ldapService.DeleteUser(distinguishedName);
            }
            catch (Exception e)
            {
                return await Task.FromResult(IdentityResult.Failed(new IdentityError() { Code = "LdapUserDeleteFailed", Description = e.Message ?? "The user could not be deleted." }));
            }

            return await Task.FromResult(IdentityResult.Success);
        }

        public Task<bool> LdapEnableAsync()
        {
            return Task.FromResult(this._ldapService.Enable());
        }

        public  IQueryable<LdapUser> Users => this._ldapService.GetAllUsers().AsQueryable();
    }
}
