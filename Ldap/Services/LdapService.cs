//using RegionalIdentity.Extensions;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Principal;
using System.Text;
using SafetyAD.Ldap.Settings;
using SafetyAD.Ldap.Models;

namespace SafetyAD.Ldap.Services
{
    public class LdapService : ILdapService
    {
        private readonly string _searchBase;

        private readonly LdapSettings _ldapSettings;

        private readonly string[] _attributes =
        {
            "objectSid", "objectGUID", "objectCategory", "objectClass", "memberOf", "name", "cn", "distinguishedName",
            "sAMAccountName", "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "description",
            "telephoneNumber", "mail", "streetAddress", "postalCode", "l", "st", "co", "c"
        };

        public LdapService(IOptions<LdapSettings> ldapSettingsOptions)
        {
            this._ldapSettings = ldapSettingsOptions.Value;
            this._searchBase = this._ldapSettings.SearchBase;
        }

        private ILdapConnection GetConnection()
        {
            var ldapConnection = new LdapConnection() { SecureSocketLayer = this._ldapSettings.UseSSL };

            //Connect function will create a socket connection to the server - Port 389 for insecure and 3269 for secure    
            ldapConnection.Connect(this._ldapSettings.ServerName, this._ldapSettings.ServerPort);
            //Bind function with null user dn and password value will perform anonymous bind to LDAP server 
            ldapConnection.Bind(this._ldapSettings.Credentials.DomainUserName, this._ldapSettings.Credentials.Password);

            return ldapConnection;
        }

        public ICollection<SafetyAD.Ldap.Models.LdapEntry> GetGroups(string groupName, bool getChildGroups = false)
        {
            var groups = new Collection<SafetyAD.Ldap.Models.LdapEntry>();

            var filter = $"(&(objectClass=group)(cn={groupName}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                    this._searchBase,
                    LdapConnection.ScopeSub,
                    filter,
                    this._attributes,
                    false);

                LdapMessage message;
                /*
                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    var entry = searchResultMessage.Entry;

                    groups.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));

                    if (!getChildGroups)
                    {
                        continue;
                    }

                    foreach (var child in this.GetChildren<SafetyAD.Ldap.Models.LdapEntry>(string.Empty, entry.DN))
                    {
                        groups.Add(child);
                    }
                }*/
            }

            return groups;
        }

        public ICollection<LdapUser> GetAllUsers()
        {
            return this.GetUsersInGroups(null);
        }

        public ICollection<LdapUser> GetUsersInGroup(string group)
        {
            return this.GetUsersInGroups(this.GetGroups(group));
        }

        public ICollection<LdapUser> GetUsersInGroups(ICollection<SafetyAD.Ldap.Models.LdapEntry> groups)
        {
            var users = new Collection<LdapUser>();

            /*
            if (groups == null || !groups.Any())
            {
                users.AddRange(this.GetChildren<LdapUser>(this._searchBase));
            }
            else
            {
                foreach (var group in groups)
                {
                    users.AddRange(this.GetChildren<LdapUser>(this._searchBase, @group.DistinguishedName));
                }
            }
            */
            return users;
        }

        public ICollection<LdapUser> GetUsersByEmailAddress(string emailAddress)
        {
            var users = new Collection<LdapUser>();

            var filter = $"(&(objectClass=user)(mail={emailAddress}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                    this._searchBase,
                    LdapConnection.ScopeSub,
                    filter,
                    this._attributes,
                    false);

                LdapMessage message;
                /*
                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    users.Add(this.CreateUserFromAttributes(this._searchBase,
                        searchResultMessage.Entry.getAttributeSet()));
                }*/
            }

            return users;
        }

        public LdapUser GetUserByUserNameFirst(string userNameFirst)
        {
            LdapUser user = null;

            var filter = $"(&(objectClass=user)(name={userNameFirst}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                    this._searchBase,
                    LdapConnection.ScopeSub,
                    filter,
                    this._attributes,
                    false);

                LdapMessage message;

                /*
                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    user = this.CreateUserFromAttributes(this._searchBase, searchResultMessage.Entry.getAttributeSet());
                }*/
            }

            return user;
        }

        public LdapUser GetUserByUserName(string UserName)
        {
            LdapUser user = null;

            var filter = $"(&(objectClass=user)(SAMAccountName={UserName}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                    this._searchBase,
                    LdapConnection.ScopeSub,
                    filter,
                    this._attributes,
                    false);

                LdapMessage message;
                /*
                while ((message = search.getResponse()) != null)
                {
                    if (!(message is LdapSearchResult searchResultMessage))
                    {
                        continue;
                    }

                    user = this.CreateUserFromAttributes(this._searchBase, searchResultMessage.Entry.getAttributeSet());
                }*/
            }

            return user;
        }

        public LdapUser GetAdministrator()
        {
            var name = this._ldapSettings.Credentials.DomainUserName.Substring(
                this._ldapSettings.Credentials.DomainUserName.IndexOf("\\", StringComparison.Ordinal) != -1
                    ? this._ldapSettings.Credentials.DomainUserName.IndexOf("\\", StringComparison.Ordinal) + 1
                    : 0);

            return this.GetUserByUserName(name);
        }

        public void AddUser(LdapUser user, string password)
        {
            var dn = $"CN={user.FirstName} {user.LastName},{this._ldapSettings.ContainerName}";

            var attributeSet = new LdapAttributeSet
            {
                new LdapAttribute("instanceType", "4"),
                new LdapAttribute("objectCategory", $"CN=Person,CN=Schema,CN=Configuration,{this._ldapSettings.DomainDistinguishedName}"),
                new LdapAttribute("objectClass", new[] {"top", "person", "organizationalPerson", "user"}),
                new LdapAttribute("name", user.UserName),
                new LdapAttribute("cn", $"{user.FirstName} {user.LastName}"),
                new LdapAttribute("sAMAccountName", user.UserName),
                new LdapAttribute("userPrincipalName", user.UserName),
                new LdapAttribute("unicodePwd", Convert.ToBase64String(Encoding.Unicode.GetBytes($"\"{user.Password}\""))),
                new LdapAttribute("userAccountControl", user.MustChangePasswordOnNextLogon ? "544" : "512"),
                new LdapAttribute("givenName", user.FirstName),
                new LdapAttribute("sn", user.LastName),
                new LdapAttribute("mail", user.EmailAddress)
            };

            if (user.DisplayName != null)
            {
                attributeSet.Add(new LdapAttribute("displayName", user.DisplayName));
            }

            if (user.Description != null)
            {
                attributeSet.Add(new LdapAttribute("description", user.Description));
            }
            if (user.Phone != null)
            {
                attributeSet.Add(new LdapAttribute("telephoneNumber", user.Phone));
            }
            if (user.Address?.Street != null)
            {
                attributeSet.Add(new LdapAttribute("streetAddress", user.Address.Street));
            }
            if (user.Address?.City != null)
            {
                attributeSet.Add(new LdapAttribute("l", user.Address.City));
            }
            if (user.Address?.PostalCode != null)
            {
                attributeSet.Add(new LdapAttribute("postalCode", user.Address.PostalCode));
            }
            if (user.Address?.StateName != null)
            {
                attributeSet.Add(new LdapAttribute("st", user.Address.StateName));
            }
            if (user.Address?.CountryName != null)
            {
                attributeSet.Add(new LdapAttribute("co", user.Address.CountryName));
            }
            if (user.Address?.CountryCode != null)
            {
                attributeSet.Add(new LdapAttribute("c", user.Address.CountryCode));
            }
            
            var newEntry = new Novell.Directory.Ldap.LdapEntry(dn, attributeSet);

            using (var ldapConnection = this.GetConnection())
            {
                ldapConnection.Add(newEntry);
            }
        }

        public void DeleteUser(string distinguishedName)
        {
            using (var ldapConnection = this.GetConnection())
            {
                ldapConnection.Delete(distinguishedName);
            }
        }


        public bool Authenticate(string distinguishedName, string password)
        {
            using (var ldapConnection = new LdapConnection() { SecureSocketLayer = true })
            {
                ldapConnection.Connect(this._ldapSettings.ServerName, this._ldapSettings.ServerPort);

                try
                {
                    ldapConnection.Bind(distinguishedName, password);

                    return true;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        public bool Enable()
        {
            return this._ldapSettings.Enable;
        }

        private ICollection<T> GetChildren<T>(string searchBase, string groupDistinguishedName = null)
            where T : ILdapEntry, new()
        {
            var entries = new Collection<T>();

            var objectCategory = "*";
            var objectClass = "*";

            if (typeof(T) == typeof(SafetyAD.Ldap.Models.LdapEntry))
            {
                objectClass = "group";
                objectCategory = "group";

                //entries = this.GetChildren(this._searchBase, groupDistinguishedName, objectCategory, objectClass)
                //    .Cast<T>().ToCollection();

            }

            if (typeof(T) == typeof(LdapUser))
            {
                objectCategory = "person";
                objectClass = "user";

                //entries = this.GetChildren(this._searchBase, null, objectCategory, objectClass).Cast<T>()
                //    .ToCollection();

            }

            return entries;
        }

        private ICollection<ILdapEntry> GetChildren(string searchBase, string groupDistinguishedName = null,
            string objectCategory = "*", string objectClass = "*")
        {
            var allChildren = new Collection<ILdapEntry>();

            var filter = string.IsNullOrEmpty(groupDistinguishedName)
                ? $"(&(objectCategory={objectCategory})(objectClass={objectClass}))"
                : $"(&(objectCategory={objectCategory})(objectClass={objectClass})(memberOf={groupDistinguishedName}))";

            using (var ldapConnection = this.GetConnection())
            {
                var search = ldapConnection.Search(
                    searchBase,
                    LdapConnection.ScopeSub,
                    filter,
                    this._attributes,
                    false);

                LdapMessage message;

                //while ((message = search.getResponse()) != null)
                //{
                //    if (!(message is LdapSearchResult searchResultMessage))
                //    {
                //        continue;
                //    }

                //    var entry = searchResultMessage.Entry;

                //    if (objectClass == "group")
                //    {
                //        allChildren.Add(this.CreateEntryFromAttributes(entry.DN, entry.getAttributeSet()));

                //        foreach (var child in this.GetChildren(string.Empty, entry.DN, objectCategory, objectClass))
                //        {
                //            allChildren.Add(child);
                //        }
                //    }

                //    if (objectClass == "user")
                //    {
                //        allChildren.Add(this.CreateUserFromAttributes(entry.DN, entry.getAttributeSet()));
                //    }

                //    ;
                //}
            }

            return allChildren;
        }

        private LdapUser CreateUserFromAttributes(string distinguishedName, LdapAttributeSet attributeSet)
        {
            var ldapUser = new LdapUser
            {
                ObjectSid = attributeSet.GetAttribute("objectSid")?.StringValue,
                ObjectGuid = attributeSet.GetAttribute("objectGUID")?.StringValue,
                ObjectCategory = attributeSet.GetAttribute("objectCategory")?.StringValue,
                ObjectClass = attributeSet.GetAttribute("objectClass")?.StringValue,
                IsDomainAdmin = attributeSet.GetAttribute("memberOf") != null && attributeSet.GetAttribute("memberOf").StringValueArray.Contains("CN=Domain Admins," + this._ldapSettings.SearchBase),
                MemberOf = attributeSet.GetAttribute("memberOf")?.StringValueArray,
                CommonName = attributeSet.GetAttribute("cn")?.StringValue,
                UserName = attributeSet.GetAttribute("name")?.StringValue,
                SamAccountName = attributeSet.GetAttribute("sAMAccountName")?.StringValue,
                UserPrincipalName = attributeSet.GetAttribute("userPrincipalName")?.StringValue,
                Name = attributeSet.GetAttribute("name")?.StringValue,
                DistinguishedName = attributeSet.GetAttribute("distinguishedName")?.StringValue ?? distinguishedName,
                DisplayName = attributeSet.GetAttribute("displayName")?.StringValue,
                FirstName = attributeSet.GetAttribute("givenName")?.StringValue,
                LastName = attributeSet.GetAttribute("sn")?.StringValue,
                Description = attributeSet.GetAttribute("description")?.StringValue,
                Phone = attributeSet.GetAttribute("telephoneNumber")?.StringValue,
                EmailAddress = attributeSet.GetAttribute("mail")?.StringValue,
                Address = new LdapAddress
                {
                    Street = attributeSet.GetAttribute("streetAddress")?.StringValue,
                    City = attributeSet.GetAttribute("l")?.StringValue,
                    PostalCode = attributeSet.GetAttribute("postalCode")?.StringValue,
                    StateName = attributeSet.GetAttribute("st")?.StringValue,
                    CountryName = attributeSet.GetAttribute("co")?.StringValue,
                    CountryCode = attributeSet.GetAttribute("c")?.StringValue
                },

                SamAccountType = int.Parse(attributeSet.GetAttribute("sAMAccountType")?.StringValue ?? "0"),
            };

            return ldapUser;
        }

        private SafetyAD.Ldap.Models.LdapEntry CreateEntryFromAttributes(string distinguishedName, LdapAttributeSet attributeSet)
        {
            return new SafetyAD.Ldap.Models.LdapEntry
            {
                ObjectSid = attributeSet.GetAttribute("objectSid")?.StringValue,
                ObjectGuid = attributeSet.GetAttribute("objectGUID")?.StringValue,
                ObjectCategory = attributeSet.GetAttribute("objectCategory")?.StringValue,
                ObjectClass = attributeSet.GetAttribute("objectClass")?.StringValue,
                CommonName = attributeSet.GetAttribute("cn")?.StringValue,
                Name = attributeSet.GetAttribute("name")?.StringValue,
                DistinguishedName = attributeSet.GetAttribute("distinguishedName")?.StringValue ?? distinguishedName,
                SamAccountName = attributeSet.GetAttribute("sAMAccountName")?.StringValue,
                SamAccountType = int.Parse(attributeSet.GetAttribute("sAMAccountType")?.StringValue ?? "0"),
            };
        }

        private SecurityIdentifier GetDomainSid()
        {
            var administratorAcount = new NTAccount(this._ldapSettings.DomainName, "administrator");
            var administratorSId = (SecurityIdentifier)administratorAcount.Translate(typeof(SecurityIdentifier));
            return administratorSId.AccountDomainSid;
        }

    }
}
