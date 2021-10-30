using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WIMP_Server.Models.Auth
{
    public class ApiKey
    {
        [Key]
        [Required]
        public int Id { get; set; }

        [Required]
        public string Owner { get; set; }

        [Required]
        public string Key { get; set; }

        [Required]
        public DateTime Created { get; set; }

        [NotMapped]
        public IEnumerable<ApiKeyRole> Roles { get; set; }
    }
}