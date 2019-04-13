using System;

namespace WebAPISecure.Models
{
    public class Order
    {
        public int OrderID { get; set; }
        public string CustomerName { get; set; }
        public string ShipperCity { get; set; }
        public bool IsShipped { get; set; }
    }
}
