using Microsoft.AspNetCore.Authorization;

namespace WIMP_Server.Auth.Policies.Requirements
{
    public class OnlyAdminsRequirement : IAuthorizationRequirement
    {
    }
}