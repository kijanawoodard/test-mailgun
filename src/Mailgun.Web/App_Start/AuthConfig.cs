using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Mailgun.Web.Controllers;
using Microsoft.Web.WebPages.OAuth;
using Mailgun.Web.Models;

namespace Mailgun.Web
{
	public static class AuthConfig
	{
		public static void RegisterAuth()
		{
			// To let users of this site log in using their accounts from other sites such as Microsoft, Facebook, and Twitter,
			// you must update this site. For more information visit http://go.microsoft.com/fwlink/?LinkID=252166

			//OAuthWebSecurity.RegisterMicrosoftClient(
			//    clientId: "",
			//    clientSecret: "");

			//OAuthWebSecurity.RegisterTwitterClient(
			//    consumerKey: "",
			//    consumerSecret: "");

			//OAuthWebSecurity.RegisterFacebookClient(
			//    appId: "",
			//    appSecret: "");

			OAuthWebSecurity.RegisterGoogleClient();

//			OAuthWebSecurity.RegisterClient(new BasecampAuthController.BasecampOAuth2Client("a97185302e03926bcc6d8bc2a008b1b4293268c7", "b4ae9a20491e3775b3ca65b497a1dba5d367eb51"));
		}
	}
}
