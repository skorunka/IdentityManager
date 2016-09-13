namespace TaxiGun.Server.IdentityServer.Code
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using System.Security.Claims;
	using System.Threading.Tasks;
	using IdentityManager;
	using JetBrains.Annotations;
	using Microsoft.AspNetCore.Identity;
	using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

	public class AspNetCoreIdentityManagerService<TUser, TRole> : IIdentityManagerService
		where TRole : IdentityRole, new()
		where TUser : IdentityUser, new()
	{
		private readonly Func<Task<IdentityManagerMetadata>> metadataFunc;

		protected RoleManager<TRole> roleManager;

		protected UserManager<TUser> userManager;

		public string RoleClaimType { get; set; }

		public virtual Task<IdentityManagerMetadata> GetMetadataAsync()
		{
			return this.metadataFunc();
		}

		public virtual Task<IdentityManagerResult<QueryResult<UserSummary>>> QueryUsersAsync(string filter, int start, int count)
		{
			var query =
				from user in this.userManager.Users
				orderby user.UserName
				select user;

			if (!string.IsNullOrWhiteSpace(filter))
			{
				query =
					from user in query
					where user.UserName.Contains(filter)
					orderby user.UserName
					select user;
			}

			var total = query.Count();
			var users = query.Skip(start).Take(count).ToArray();

			var result = new QueryResult<UserSummary>
			{
				Start = start,
				Count = count,
				Total = total,
				Filter = filter,
				Items = users.Select(x =>
									{
										var user = new UserSummary
										{
											Subject = x.Id.ToString(),
											Username = x.UserName,
											Name = this.DisplayNameFromUser(x)
										};

										return user;
									}).ToArray()
			};

			return Task.FromResult(new IdentityManagerResult<QueryResult<UserSummary>>(result));
		}

		public virtual async Task<IdentityManagerResult<CreateResult>> CreateUserAsync([NotNull] IEnumerable<PropertyValue> properties)
		{
			if (properties == null)
			{
				throw new ArgumentNullException(nameof(properties));
			}

			var usernameClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Username);
			var passwordClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Password);

			var username = usernameClaim.Value;
			var password = passwordClaim.Value;

			string[] exclude = { Constants.ClaimTypes.Username, Constants.ClaimTypes.Password };
			var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

			var metadata = await this.GetMetadataAsync();
			var createProps = metadata.UserMetadata.GetCreateProperties();

			var user = new TUser { UserName = username };
			foreach (var prop in otherProperties)
			{
				var propertyResult = this.SetUserProperty(createProps, user, prop.Type, prop.Value);
				if (!propertyResult.IsSuccess)
				{
					return new IdentityManagerResult<CreateResult>(propertyResult.Errors.ToArray());
				}
			}

			var result = await this.userManager.CreateAsync(user, password);
			if (!result.Succeeded)
			{
				return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
			}

			return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = user.Id });
		}

		public virtual async Task<IdentityManagerResult> DeleteUserAsync(string key)
		{
			var user = await this.userManager.FindByIdAsync(key);
			if (user == null)
			{
				return new IdentityManagerResult("Invalid subject");
			}

			var result = await this.userManager.DeleteAsync(user);
			if (!result.Succeeded)
			{
				return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
			}

			return IdentityManagerResult.Success;
		}

		public virtual async Task<IdentityManagerResult<UserDetail>> GetUserAsync(string key)
		{
			var user = await this.userManager.FindByIdAsync(key);
			if (user == null)
			{
				return new IdentityManagerResult<UserDetail>((UserDetail)null);
			}

			var result = new UserDetail
			{
				Subject = key,
				Username = user.UserName,
				Name = this.DisplayNameFromUser(user)
			};

			var metadata = await this.GetMetadataAsync();

			var props =
				from prop in metadata.UserMetadata.UpdateProperties
				select new PropertyValue
				{
					Type = prop.Type,
					Value = this.GetUserProperty(prop, user)
				};
			result.Properties = props.ToArray();

			if (this.userManager.SupportsUserClaim)
			{
				var userClaims = await this.userManager.GetClaimsAsync(user);
				var claims = new List<ClaimValue>();
				if (userClaims != null)
				{
					claims.AddRange(userClaims.Select(x => new ClaimValue { Type = x.Type, Value = x.Value }));
				}
				result.Claims = claims.ToArray();
			}

			return new IdentityManagerResult<UserDetail>(result);
		}

		public virtual async Task<IdentityManagerResult> SetUserPropertyAsync(string key, string type, string value)
		{
			var user = await this.userManager.FindByIdAsync(key);
			if (user == null)
			{
				return new IdentityManagerResult("Invalid subject");
			}

			var errors = this.ValidateUserProperty(type, value).ToArray();
			if (errors.Any())
			{
				return new IdentityManagerResult(errors);
			}

			var metadata = await this.GetMetadataAsync();
			var propResult = this.SetUserProperty(metadata.UserMetadata.UpdateProperties, user, type, value);
			if (!propResult.IsSuccess)
			{
				return propResult;
			}

			var result = await this.userManager.UpdateAsync(user);
			if (!result.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.Select(x => x.Description).ToArray());
			}

			return IdentityManagerResult.Success;
		}

		public virtual async Task<IdentityManagerResult> AddUserClaimAsync(string key, string type, string value)
		{
			var user = await this.userManager.FindByIdAsync(key);
			if (user == null)
			{
				return new IdentityManagerResult("Invalid subject");
			}

			var existingClaims = await this.userManager.GetClaimsAsync(user);
			if (!existingClaims.Any(x => (x.Type == type) && (x.Value == value)))
			{
				var result = await this.userManager.AddClaimAsync(user, new Claim(type, value));
				if (!result.Succeeded)
				{
					return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
				}
			}

			return IdentityManagerResult.Success;
		}

		public virtual async Task<IdentityManagerResult> RemoveUserClaimAsync(string key, string type, string value)
		{
			var user = await this.userManager.FindByIdAsync(key);
			if (user == null)
			{
				return new IdentityManagerResult("Invalid subject");
			}

			var result = await this.userManager.RemoveClaimAsync(user, new Claim(type, value));
			if (!result.Succeeded)
			{
				return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
			}

			return IdentityManagerResult.Success;
		}

		public virtual async Task<IdentityManagerResult<CreateResult>> CreateRoleAsync(IEnumerable<PropertyValue> properties)
		{
			this.ValidateSupportsRoles();

			var nameClaim = properties.Single(x => x.Type == Constants.ClaimTypes.Name);

			var name = nameClaim.Value;

			string[] exclude = { Constants.ClaimTypes.Name };
			var otherProperties = properties.Where(x => !exclude.Contains(x.Type)).ToArray();

			var metadata = await this.GetMetadataAsync();
			var createProps = metadata.RoleMetadata.GetCreateProperties();

			var role = new TRole { Name = name };
			foreach (var prop in otherProperties)
			{
				var roleResult = this.SetRoleProperty(createProps, role, prop.Type, prop.Value);
				if (!roleResult.IsSuccess)
				{
					return new IdentityManagerResult<CreateResult>(roleResult.Errors.ToArray());
				}
			}

			var result = await this.roleManager.CreateAsync(role);
			if (!result.Succeeded)
			{
				return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
			}

			return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = role.Id });
		}

		public virtual async Task<IdentityManagerResult> DeleteRoleAsync(string key)
		{
			this.ValidateSupportsRoles();

			var role = await this.roleManager.FindByIdAsync(key);
			if (role == null)
			{
				return new IdentityManagerResult("Invalid subject");
			}

			var result = await this.roleManager.DeleteAsync(role);
			if (!result.Succeeded)
			{
				return new IdentityManagerResult<CreateResult>(result.Errors.Select(x => x.Description).ToArray());
			}

			return IdentityManagerResult.Success;
		}

		public virtual async Task<IdentityManagerResult<RoleDetail>> GetRoleAsync(string key)
		{
			this.ValidateSupportsRoles();

			var role = await this.roleManager.FindByIdAsync(key);
			if (role == null)
			{
				return new IdentityManagerResult<RoleDetail>((RoleDetail)null);
			}

			var result = new RoleDetail
			{
				Subject = key,
				Name = role.Name

				// Description
			};

			var metadata = await this.GetMetadataAsync();

			var props =
				from prop in metadata.RoleMetadata.UpdateProperties
				select new PropertyValue
				{
					Type = prop.Type,
					Value = this.GetRoleProperty(prop, role)
				};
			result.Properties = props.ToArray();

			return new IdentityManagerResult<RoleDetail>(result);
		}

		public virtual Task<IdentityManagerResult<QueryResult<RoleSummary>>> QueryRolesAsync(string filter, int start, int count)
		{
			this.ValidateSupportsRoles();

			if (start < 0)
			{
				start = 0;
			}
			if (count < 0)
			{
				count = int.MaxValue;
			}

			var query = this.roleManager.Roles;

			if (!string.IsNullOrWhiteSpace(filter))
			{
				query = this.roleManager.Roles.Where(role => role.Name.Contains(filter));
			}

			var total = query.Count();
			var roles = query.Skip(start).Take(count).ToArray();

			var result = new QueryResult<RoleSummary>
			{
				Start = start,
				Count = count,
				Total = total,
				Filter = filter,
				Items = roles.Select(x =>
									{
										var user = new RoleSummary
										{
											Subject = x.Id.ToString(),
											Name = x.Name

											// Description
										};

										return user;
									}).ToArray()
			};

			return Task.FromResult(new IdentityManagerResult<QueryResult<RoleSummary>>(result));
		}

		public virtual async Task<IdentityManagerResult> SetRolePropertyAsync(string key, string type, string value)
		{
			this.ValidateSupportsRoles();

			var role = await this.roleManager.FindByIdAsync(key);
			if (role == null)
			{
				return new IdentityManagerResult("Invalid subject");
			}

			var errors = this.ValidateRoleProperty(type, value).ToArray();
			if (errors.Any())
			{
				return new IdentityManagerResult(errors);
			}

			var metadata = await this.GetMetadataAsync();
			var result = this.SetRoleProperty(metadata.RoleMetadata.UpdateProperties, role, type, value);
			if (!result.IsSuccess)
			{
				return result;
			}

			var updateResult = await this.roleManager.UpdateAsync(role);
			if (!updateResult.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.ToArray());
			}

			return IdentityManagerResult.Success;
		}

		public virtual IdentityManagerMetadata GetStandardMetadata(bool includeAccountProperties = true)
		{
			var update = new List<PropertyMetadata>();
			if (this.userManager.SupportsUserPassword)
			{
				update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, x => null, this.SetPassword, "Password", PropertyDataType.Password, true));
			}
			if (this.userManager.SupportsUserEmail)
			{
				update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Email, this.GetEmail, this.SetEmail, "Email", PropertyDataType.Email));
			}
			if (this.userManager.SupportsUserPhoneNumber)
			{
				update.Add(PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Phone, this.GetPhone, this.SetPhone, "Phone", PropertyDataType.String));
			}
			if (this.userManager.SupportsUserTwoFactor)
			{
				update.Add(PropertyMetadata.FromFunctions<TUser, bool>("two_factor", this.GetTwoFactorEnabled, this.SetTwoFactorEnabled, "Two Factor Enabled", PropertyDataType.Boolean));
			}
			if (this.userManager.SupportsUserLockout)
			{
				update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked_enabled", this.GetLockoutEnabled, this.SetLockoutEnabled, "Lockout Enabled", PropertyDataType.Boolean));
				update.Add(PropertyMetadata.FromFunctions<TUser, bool>("locked", this.GetLockedOut, this.SetLockedOut, "Locked Out", PropertyDataType.Boolean));
			}

			if (includeAccountProperties)
			{
				update.AddRange(PropertyMetadata.FromType<TUser>());
			}

			var create = new List<PropertyMetadata>
			{
				PropertyMetadata.FromProperty<TUser>(x => x.UserName, Constants.ClaimTypes.Username, required: true),
				PropertyMetadata.FromFunctions<TUser, string>(Constants.ClaimTypes.Password, x => null, this.SetPassword, "Password", PropertyDataType.Password, true)
			};

			var user = new UserMetadata
			{
				SupportsCreate = true,
				SupportsDelete = true,
				SupportsClaims = this.userManager.SupportsUserClaim,
				CreateProperties = create,
				UpdateProperties = update
			};

			var role = new RoleMetadata
			{
				RoleClaimType = this.RoleClaimType,
				SupportsCreate = true,
				SupportsDelete = true,
				CreateProperties = new[]
				{
					PropertyMetadata.FromProperty<TRole>(x => x.Name, Constants.ClaimTypes.Name, required: true)
				}
			};

			var meta = new IdentityManagerMetadata
			{
				UserMetadata = user,
				RoleMetadata = role
			};
			return meta;
		}

		public virtual PropertyMetadata GetMetadataForClaim(string type, string name = null, PropertyDataType dataType = PropertyDataType.String, bool required = false)
		{
			return PropertyMetadata.FromFunctions(type, this.GetForClaim(type), this.SetForClaim(type), name, dataType, required);
		}

		public virtual Func<TUser, string> GetForClaim(string type)
		{
			return user => this.userManager.GetClaimsAsync(user).Result.Where(x => x.Type == type).Select(x => x.Value).FirstOrDefault();
		}

		public virtual Func<TUser, string, IdentityManagerResult> SetForClaim(string type)
		{
			return (user, value) =>
					{
						var claims = this.userManager.GetClaimsAsync(user).Result.Where(x => x.Type == type).ToArray();
						foreach (var claim in claims)
						{
							var result = this.userManager.RemoveClaimAsync(user, claim).Result;
							if (!result.Succeeded)
							{
								return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
							}
						}

						if (!string.IsNullOrWhiteSpace(value))
						{
							var result = this.userManager.AddClaimAsync(user, new Claim(type, value)).Result;
							if (!result.Succeeded)
							{
								return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
							}
						}

						return IdentityManagerResult.Success;
					};
		}

		public virtual IdentityManagerResult SetPassword(TUser user, string password)
		{
			var token = this.userManager.GeneratePasswordResetTokenAsync(user).Result;
			var result = this.userManager.ResetPasswordAsync(user, token, password).Result;
			if (!result.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
			}

			return IdentityManagerResult.Success;
		}

		public virtual string GetEmail(TUser user)
		{
			return this.userManager.GetEmailAsync(user).Result;
		}

		public virtual IdentityManagerResult SetEmail(TUser user, string email)
		{
			var result = this.userManager.SetEmailAsync(user, email).Result;
			if (!result.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
			}

			if (!string.IsNullOrWhiteSpace(email))
			{
				var token = this.userManager.GenerateEmailConfirmationTokenAsync(user).Result;
				result = this.userManager.ConfirmEmailAsync(user, token).Result;
				if (!result.Succeeded)
				{
					return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
				}
			}

			return IdentityManagerResult.Success;
		}

		public virtual string GetPhone(TUser user)
		{
			return this.userManager.GetPhoneNumberAsync(user).Result;
		}

		public virtual IdentityManagerResult SetPhone(TUser user, string phone)
		{
			var result = this.userManager.SetPhoneNumberAsync(user, phone).Result;
			if (!result.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
			}

			if (!string.IsNullOrWhiteSpace(phone))
			{
				var token = this.userManager.GenerateChangePhoneNumberTokenAsync(user, phone).Result;
				result = this.userManager.ChangePhoneNumberAsync(user, phone, token).Result;
				if (!result.Succeeded)
				{
					return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
				}
			}

			return IdentityManagerResult.Success;
		}

		public virtual bool GetTwoFactorEnabled(TUser user)
		{
			return this.userManager.GetTwoFactorEnabledAsync(user).Result;
		}

		public virtual IdentityManagerResult SetTwoFactorEnabled(TUser user, bool enabled)
		{
			var result = this.userManager.SetTwoFactorEnabledAsync(user, enabled).Result;
			if (!result.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
			}

			return IdentityManagerResult.Success;
		}

		public virtual bool GetLockoutEnabled(TUser user)
		{
			return this.userManager.GetLockoutEnabledAsync(user).Result;
		}

		public virtual IdentityManagerResult SetLockoutEnabled(TUser user, bool enabled)
		{
			var result = this.userManager.SetLockoutEnabledAsync(user, enabled).Result;
			if (!result.Succeeded)
			{
				return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
			}

			return IdentityManagerResult.Success;
		}

		public virtual bool GetLockedOut(TUser user)
		{
			return this.userManager.GetLockoutEndDateAsync(user).Result > DateTimeOffset.UtcNow;
		}

		public virtual IdentityManagerResult SetLockedOut(TUser user, bool locked)
		{
			if (locked)
			{
				var result = this.userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue).Result;
				if (!result.Succeeded)
				{
					return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
				}
			}
			else
			{
				var result = this.userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MinValue).Result;
				if (!result.Succeeded)
				{
					return new IdentityManagerResult(result.Errors.Select(x => x.Description).First());
				}
			}

			return IdentityManagerResult.Success;
		}

		protected virtual string DisplayNameFromUser(TUser user)
		{
			if (this.userManager.SupportsUserClaim)
			{
				var claims = this.userManager.GetClaimsAsync(user).Result;
				var name = claims.Where(x => x.Type == Constants.ClaimTypes.Name).Select(x => x.Value).FirstOrDefault();
				if (!string.IsNullOrWhiteSpace(name))
				{
					return name;
				}
			}

			return null;
		}

		protected virtual IEnumerable<string> ValidateUserProperty(string type, string value)
		{
			return Enumerable.Empty<string>();
		}

		protected virtual string GetUserProperty(PropertyMetadata propMetadata, TUser user)
		{
			string val;
			if (propMetadata.TryGet(user, out val))
			{
				return val;
			}

			throw new Exception("Invalid property type " + propMetadata.Type);
		}

		protected virtual IdentityManagerResult SetUserProperty(IEnumerable<PropertyMetadata> propsMeta, TUser user, string type, string value)
		{
			IdentityManagerResult result;
			if (propsMeta.TrySet(user, type, value, out result))
			{
				return result;
			}

			throw new Exception("Invalid property type " + type);
		}

		protected virtual void ValidateSupportsRoles()
		{
			if (this.roleManager == null)
			{
				throw new InvalidOperationException("Roles Not Supported");
			}
		}

		protected virtual IEnumerable<string> ValidateRoleProperties(IEnumerable<PropertyValue> properties)
		{
			return properties.Select(x => this.ValidateRoleProperty(x.Type, x.Value)).Aggregate((x, y) => x.Concat(y));
		}

		protected virtual IEnumerable<string> ValidateRoleProperty(string type, string value)
		{
			return Enumerable.Empty<string>();
		}

		protected virtual string GetRoleProperty(PropertyMetadata propMetadata, TRole role)
		{
			string val;
			if (propMetadata.TryGet(role, out val))
			{
				return val;
			}

			throw new Exception("Invalid property type " + propMetadata.Type);
		}

		protected virtual IdentityManagerResult SetRoleProperty(IEnumerable<PropertyMetadata> propsMeta, TRole role, string type, string value)
		{
			IdentityManagerResult result;
			if (propsMeta.TrySet(role, type, value, out result))
			{
				return result;
			}

			throw new Exception("Invalid property type " + type);
		}

		#region ctors

		private AspNetCoreIdentityManagerService(UserManager<TUser> userManager, RoleManager<TRole> roleManager)
		{
			if (userManager == null)
			{
				throw new ArgumentNullException(nameof(userManager));
			}

			if (roleManager == null)
			{
				throw new ArgumentNullException(nameof(roleManager));
			}

			if (!userManager.SupportsQueryableUsers)
			{
				throw new InvalidOperationException("UserManager must support queryable users.");
			}

			this.userManager = userManager;
			this.roleManager = roleManager;

			this.RoleClaimType = Constants.ClaimTypes.Role;
		}

		public AspNetCoreIdentityManagerService(UserManager<TUser> userManager, RoleManager<TRole> roleManager, bool includeAccountProperties = true)
			: this(userManager, roleManager)
		{
			this.metadataFunc = () => Task.FromResult(this.GetStandardMetadata(includeAccountProperties));
		}

		public AspNetCoreIdentityManagerService(UserManager<TUser> userManager, RoleManager<TRole> roleManager, IdentityManagerMetadata metadata)
			: this(userManager, roleManager, () => Task.FromResult(metadata))
		{
		}

		public AspNetCoreIdentityManagerService(UserManager<TUser> userManager, RoleManager<TRole> roleManager, Func<Task<IdentityManagerMetadata>> metadataFunc)
			: this(userManager, roleManager)
		{
			this.metadataFunc = metadataFunc;
		}

		#endregion
	}
}
