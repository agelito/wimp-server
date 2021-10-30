using System.ComponentModel.DataAnnotations;

namespace WIMP_Server.Models.Auth
{
    public class ApiKeyRole
    {
        [Required]
        public int ApiKeyId { get; set; }

        [Required]
        public string Role { get; set; }

        public ApiKey Owner { get; set; }
    }
}