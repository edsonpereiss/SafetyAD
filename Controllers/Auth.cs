using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace SafetyAD.Controllers
{
    class ResultJson
    {
        public object data {get; set;}
        public string message {get; set;}        
    }

    [ApiController]
    [Route("[controller]")]
    public class Auth : ControllerBase
    {
        [HttpGet]
        public object Get(string key  = null, string user = null, string password = null)
        {
            ResultJson result = new ResultJson();
            result.data = true;
            result.message = "";
             if (string.IsNullOrEmpty(key))
             {
                result.data = false;
                result.message = "Invalid Key";
                return result;
             }
             if (string.IsNullOrEmpty(password))
             {
                result.data = false;
                result.message = "Invalid password";
                return result;
             }
             if (string.IsNullOrEmpty(user))
             {
                result.data = false;
                result.message = "Invalid user";
                return result;
             }
            return result;
        }
    }
}