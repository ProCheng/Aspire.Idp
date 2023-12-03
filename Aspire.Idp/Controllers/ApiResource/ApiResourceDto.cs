using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Aspire.Idp.Controllers.ApiResource
{
    public class ApiResourceDto
    {
        /// <summary>
        /// 大于0表示进行修改
        /// </summary>
        public int Id { get; set; }
        public string Name { get; set; }
        public string DisplayName { get; set; }
        public string Description { get; set; }
        public string UserClaims { get; set; }
        public string Scopes { get; set; }
    }
}
