using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using WIMP_Server.Models.Auth;

namespace WIMP_Server.Data.Auth
{
    public class ApiKeyRepository : IApiKeyRepository
    {
        private readonly WimpDbContext _wimpDbContext;

        public ApiKeyRepository(WimpDbContext wimpDbContext)
        {
            _wimpDbContext = wimpDbContext;
        }

        public Task<ApiKey> Get(string apiKey)
        {
            return Task.FromResult(_wimpDbContext.ApiKeys
                .Include(apiKey => apiKey.Roles)
                .FirstOrDefault(key => key.Key == apiKey));
        }
    }
}