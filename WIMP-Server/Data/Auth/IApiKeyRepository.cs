using System.Threading.Tasks;
using WIMP_Server.Models.Auth;

namespace WIMP_Server.Data.Auth
{
    public interface IApiKeyRepository
    {
        Task<ApiKey> Get(string apiKey);
    }
}