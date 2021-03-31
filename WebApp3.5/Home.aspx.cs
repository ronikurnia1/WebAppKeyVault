using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using WebApp.Helpers;

namespace WebApp
{
    public partial class Home : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            GetClientAssertion();            
        }


        private void GetClientAssertion()
        {
            string clientAssetionCode = ClientAssetionGenerator.GetSignedClientAssertion();
            Label1.Text = clientAssetionCode;
        }
    }
}