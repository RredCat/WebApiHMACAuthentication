using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using WebAPISecure.Models;

namespace WebAPISecure.Controllers
{
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = "api")]
    public class ValuesController : Controller
    {
        // GET api/values
        [HttpGet]
        public IEnumerable<string> Get() => new [] { "value1", "value2" };

        [HttpPost]
        public void Post([FromBody]Order order)
        {
        }
    }
}