using System.Collections.Generic;

namespace WIMP_Server.Auth.Roles
{
    public static class Role
    {
        public const string Admin = nameof(Admin);
        public const string User = nameof(User);

        public const string IntelWrite = nameof(IntelWrite);
        public const string IntelRead = nameof(IntelRead);

        public const string UserRegister = nameof(UserRegister);
        public const string UserCreate = nameof(UserCreate);
        public const string UserDelete = nameof(UserDelete);

        public static IEnumerable<string> AllRoles { get; } = new List<string>
        {
            UserDelete,
            UserCreate,
            UserRegister,
            IntelRead,
            IntelWrite,
            Admin,
            User
        };
    }
}