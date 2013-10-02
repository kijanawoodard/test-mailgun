using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using DotNetOpenAuth.AspNet;
using DotNetOpenAuth.AspNet.Clients;
using DotNetOpenAuth.Messaging;
using Mailgun.Web.Models;
using Microsoft.Web.WebPages.OAuth;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using RestSharp;
using SimpleAuthentication.Core;
using SimpleAuthentication.Mvc;
using WebMatrix.WebData;

namespace Mailgun.Web.Controllers
{
	//https://github.com/37signals/api/blob/master/sections/authentication.md
	//https://github.com/mj1856/DotNetOpenAuth.GoogleOAuth2
	//http://stackoverflow.com/questions/12680257/how-can-i-get-extradata-from-oauthwebsecurity
    public class BasecampAuthController : Controller
    {
		public ActionResult Index()
		{
			return new ExternalLoginResult("basecamp", Url.Action("Callback", "BasecampAuth", new {}, "http"));
		}

		[AllowAnonymous]
		public ActionResult Callback(string code)
		{
//			AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(Url.Action("Callback", new { returnUrl = "/" }));

			var client = 
				OAuthWebSecurity
					.RegisteredClientData
					.First(x => x.AuthenticationClient.ProviderName == "basecamp").AuthenticationClient;

//			var securityManager = new OpenAuthSecurityManager(HttpContext, client, new WebPagesOAuthDataProvider());
//			var result = securityManager.VerifyAuthentication(returnUrl);

			var result = VerifyAuthentication(client, Url.Action("Callback", "BasecampAuth", new {}, "http"));

			return Json(result.ExtraData, JsonRequestBehavior.AllowGet);
		}

		public AuthenticationResult VerifyAuthentication(IAuthenticationClient authenticationProvider, string returnUrl)
		{
			string parameterValue;
//			if (!this.ValidateRequestAgainstXsrfAttack(out parameterValue))
//			{
//				return new AuthenticationResult(false, authenticationProvider.ProviderName, null, null, null);
//			}
			OAuth2Client oAuth2Client = authenticationProvider as OAuth2Client;
			if (oAuth2Client != null)
			{
				Uri uri = new Uri(returnUrl);
//				if (!string.IsNullOrEmpty(returnUrl))
//				{
//					uri = UriHelper.ConvertToAbsoluteUri(returnUrl, HttpContext);
//				}
//				else
//				{
//					uri = MessagingUtilities.GetPublicFacingUrl(HttpContext.Request);
//				}
//				uri = uri.AttachQueryStringParameter("__provider__", authenticationProvider.ProviderName);
//				uri = uri.AttachQueryStringParameter("__sid__", parameterValue);
				AuthenticationResult result;
				try
				{
					AuthenticationResult authenticationResult = oAuth2Client.VerifyAuthentication(HttpContext, uri);
					if (!authenticationResult.IsSuccessful)
					{
						authenticationResult = new AuthenticationResult(false, authenticationProvider.ProviderName, null, null, null);
					}
					result = authenticationResult;
					return result;
				}
				catch (HttpException ex)
				{
					result = new AuthenticationResult(ex.GetBaseException(), authenticationProvider.ProviderName);
					return result;
				}
				return result;
			}

			return authenticationProvider.VerifyAuthentication(HttpContext);
		}

//		private bool ValidateRequestAgainstXsrfAttack(out string sessionId)
//		{
//			sessionId = null;
//			string text = HttpContext.Request.QueryString["__sid__"];
//			Guid guid;
//			if (!Guid.TryParse(text, out guid))
//			{
//				return false;
//			}
//			HttpCookie httpCookie = HttpContext.Request.Cookies["__csid__"];
//			if (httpCookie == null || string.IsNullOrEmpty(httpCookie.Value))
//			{
//				return false;
//			}
//			string b = null;
//			bool result;
//			try
//			{
//				byte[] protectedData = HttpServerUtility.UrlTokenDecode(httpCookie.Value);
//				byte[] bytes = MachineKeyUtil.Unprotect(protectedData, new string[]
//				{
//					"DotNetOpenAuth.AspNet.AntiXsrfToken.v1", 
//					"Token: " + text
//				});
//				b = Encoding.UTF8.GetString(bytes);
//			}
//			catch
//			{
//				result = false;
//				return result;
//			}
//			string username = OpenAuthSecurityManager.GetUsername(HttpContext);
//			bool flag = string.Equals(username, b, StringComparison.OrdinalIgnoreCase);
//			if (flag)
//			{
//				HttpCookie cookie = new HttpCookie("__csid__", string.Empty)
//				{
//					HttpOnly = true,
//					Expires = DateTime.Now.AddYears(-1)
//				};
//				HttpContext.Response.Cookies.Set(cookie);
//				goto IL_10C;
//			}
//			goto IL_10C;
//			return result;
//		IL_10C:
//			sessionId = text;
//			return flag;
//		}

		internal class ExternalLoginResult : ActionResult
		{
			public ExternalLoginResult(string provider, string returnUrl)
			{
				Provider = provider;
				ReturnUrl = returnUrl;
			}

			public string Provider { get; private set; }
			public string ReturnUrl { get; private set; }

			public override void ExecuteResult(ControllerContext context)
			{
				OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
			}
		}

		

		public class BasecampOAuth2Client : OAuth2Client
		{
			/// <summary>
			/// The authorization endpoint.
			/// </summary>
			private const string AuthorizationEndpoint = "https://launchpad.37signals.com/authorization/new";

			/// <summary>
			/// The token endpoint.
			/// </summary>
			private const string TokenEndpoint = "https://launchpad.37signals.com/authorization/token";

			/// <summary>
			/// The user info endpoint.
			/// </summary>
			private const string UserInfoEndpoint = "https://launchpad.37signals.com/authorization.json";

			/// <summary>
			/// The base uri for scopes.
			/// </summary>
			private const string ScopeBaseUri = "https://www.googleapis.com/auth/";

			/// <summary>
			/// The _app id.
			/// </summary>
			private readonly string _clientId;

			/// <summary>
			/// The _app secret.
			/// </summary>
			private readonly string _clientSecret;

			/// <summary>
			/// The requested scopes.
			/// </summary>
			private readonly string[] _requestedScopes;

			/// <summary>
			/// Creates a new Basecamp  OAuth2 client.
			/// </summary>
			/// <param name="clientId">The Basecamp Client Id</param>
			/// <param name="clientSecret">The Basecamp Client Secret</param>
			/// <param name="requestedScopes">One or more requested scopes, passed without the base URI.</param>
			public BasecampOAuth2Client(string clientId, string clientSecret, params string[] requestedScopes)
				: base("basecamp")
			{
				if (string.IsNullOrWhiteSpace(clientId))
					throw new ArgumentNullException("clientId");

				if (string.IsNullOrWhiteSpace(clientSecret))
					throw new ArgumentNullException("clientSecret");
//
//				if (requestedScopes == null)
//					throw new ArgumentNullException("requestedScopes");
//
//				if (requestedScopes.Length == 0)
//					throw new ArgumentException("One or more scopes must be requested.", "requestedScopes");

				_clientId = clientId;
				_clientSecret = clientSecret;
				_requestedScopes = requestedScopes;
			}

			protected override Uri GetServiceLoginUrl(Uri returnUrl)
			{
//				var scopes = _requestedScopes.Select(x => !x.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? ScopeBaseUri + x : x);
//				var state = string.IsNullOrEmpty(returnUrl.Query) ? string.Empty : returnUrl.Query.Substring(1);

				return BuildUri(AuthorizationEndpoint, new NameValueCollection
                {
                    { "type", "web_server" },
                    { "client_id", _clientId },
//                    { "scope", string.Join(" ", scopes) },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
//                    { "state", state },
                });
			}

			protected override IDictionary<string, string> GetUserData(string accessToken)
			{
				var uri = BuildUri(UserInfoEndpoint, new NameValueCollection { { "access_token", accessToken } });

				var webRequest = (HttpWebRequest)WebRequest.Create(uri);

				using (var webResponse = webRequest.GetResponse())
				using (var stream = webResponse.GetResponseStream())
				{
					if (stream == null)
						return null;

					using (var textReader = new StreamReader(stream))
					{
						var json = textReader.ReadToEnd();
						UserData = JsonConvert.DeserializeObject(json);
//						var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
//						return extraData;
						return new Dictionary<string, string>
						{
							{"access_token", accessToken}
						};
					}
				}
			}

			public dynamic UserData { get; set; }
			public override AuthenticationResult VerifyAuthentication(HttpContextBase context, Uri returnPageUrl)
			{
				string code = context.Request.QueryString["code"];
				string u = context.Request.Url.ToString();

				if (string.IsNullOrEmpty(code))
					return AuthenticationResult.Failed;

				string accessToken = this.QueryAccessToken(returnPageUrl, code);
				if (accessToken == null)
					return AuthenticationResult.Failed;

				IDictionary<string, string> userData = this.GetUserData(accessToken);
				if (userData == null)
					return AuthenticationResult.Failed;


				string id = UserData.identity.id;// userData["user_id"];
				string name = string.Empty;

				return new AuthenticationResult(
					isSuccessful: true, provider: "basecammp", providerUserId: id, userName: name, extraData: userData);
			}     

			protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
			{
				var postData = HttpUtility.ParseQueryString(string.Empty);
				postData.Add(new NameValueCollection
                {
                    { "type", "web_server" },
                    { "client_id", _clientId },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
					{ "client_secret", _clientSecret },
                    { "code", authorizationCode },
                    
                });
				

				var webRequest = (HttpWebRequest)WebRequest.Create(TokenEndpoint);

				webRequest.Method = "POST";
				webRequest.ContentType = "application/x-www-form-urlencoded";

				using (var s = webRequest.GetRequestStream())
				using (var sw = new StreamWriter(s))
					sw.Write(postData.ToString());

				using (var webResponse = webRequest.GetResponse())
				{
					var responseStream = webResponse.GetResponseStream();
					if (responseStream == null)
						return null;

					using (var reader = new StreamReader(responseStream))
					{
						var response = reader.ReadToEnd();
						var json = JObject.Parse(response);
						var accessToken = json.Value<string>("access_token");
						return accessToken;
					}
				}

//				var values = new Dictionary<string, string>
//				{
//					{"type", "web_server"},
//					{"client_id", _clientId},
//					{"redirect_uri", returnUrl.GetLeftPart(UriPartial.Path)},
//					{"client_secret", _clientSecret},
//					{"code", authorizationCode},
//				};
//				var builder = new UriBuilder(TokenEndpoint);
//				values.ToList().ForEach(x => builder.AppendQueryArgument(x.Key, x.Value));
//
//				using (var client = new WebClient())
//				{
//					string data = client.DownloadString(builder.Uri);
//					if (string.IsNullOrEmpty(data))
//					{
//						return null;
//					}
//
//					var parsedQueryString = HttpUtility.ParseQueryString(data);
//					return parsedQueryString["access_token"];
//				}
			}

			private static Uri BuildUri(string baseUri, NameValueCollection queryParameters)
			{
				var q = HttpUtility.ParseQueryString(string.Empty);
				q.Add(queryParameters);
				var builder = new UriBuilder(baseUri) { Query = q.ToString() };
				return builder.Uri;
			}
		}
    }

	public class SampleMvcAutoAuthenticationCallbackProvider : IAuthenticationCallbackProvider
	{
		public ActionResult Process(HttpContextBase context, AuthenticateCallbackData model)
		{
			using (var db = new UsersContext())
			{
				var userId = WebSecurity.GetUserId(HttpContext.Current.User.Identity.Name);
				var user = db.UserProfiles.First(u => u.UserId == userId);
				user.BasecampCredentials = user.BasecampCredentials ?? new BasecampCredentials();
				user.BasecampCredentials.AccessToken = model.AuthenticatedClient.AccessToken.PublicToken;
				user.BasecampCredentials.RefreshToken = model.AuthenticatedClient.AccessToken.SecretToken;

				db.SaveChanges();
			}
			
			var route = new RouteValueDictionary()
			{
				{"action", "Manage"},
				{"controller", "Account"}
			};
			return new RedirectToRouteResult(route);
			return new ContentResult
			{
				Content = model.AuthenticatedClient.UserInformation.Name
			};
			return new ViewResult
			{
				ViewName = "Home",
				ViewData = new ViewDataDictionary(new AuthenticateCallbackViewModel
				{
					AuthenticatedClient = model.AuthenticatedClient,
					Exception = model.Exception,
					ReturnUrl = model.ReturnUrl
				})
			};
		}

		public ActionResult OnRedirectToAuthenticationProviderError(HttpContextBase context, string errorMessage)
		{
			return new ContentResult
			{
				Content = errorMessage
			};
			return new ViewResult
			{
				ViewName = "Home",
				ViewData = new ViewDataDictionary(new IndexViewModel
				{
					ErrorMessage = errorMessage
				})
			};
		}

		public class AuthenticateCallbackViewModel
		{
			public IAuthenticatedClient AuthenticatedClient { get; set; }
			public Exception Exception { get; set; }
			public string ReturnUrl { get; set; }
		}

		public class IndexViewModel
		{
			public string ErrorMessage { get; set; }
		}
	}

	public class BasecampClient
	{
		private const string UserInfoEndpoint = "https://launchpad.37signals.com/authorization.json";
		private string _task;
		private string _accessToken;
		private RestClient _client;

		public void CreateTask(string task, string accessToken)
		{
			_task = task;
			_accessToken = accessToken;
			_client = new RestClient();
			_client.Authenticator = new OAuth2AuthorizationRequestHeaderAuthenticator(_accessToken);
			_client.UserAgent = "email to tasks (maily@wyldeye.com)";

			FindBasecamp();
		}

		private void FindBasecamp()
		{
			var request = new RestRequest(UserInfoEndpoint);

			var response = _client.Execute<dynamic>(request);
			var data = JsonConvert.DeserializeObject<dynamic>(response.Content);
			foreach (var account in data.accounts)
			{
				if (account.product != "bcx")
					continue;

				FindOrCreateProject(account.href);
				return;
			}
		}

		private void FindOrCreateProject(dynamic basecamp)
		{
			const string projectName = "Tasks From Email";

			var url = string.Format("{0}/projects.json", basecamp);
			var request = new RestRequest(url);

			var response = _client.Execute<dynamic>(request);
			var data = JsonConvert.DeserializeObject<dynamic>(response.Content);
			foreach (var project in data)
			{
				if (project.name != projectName)
					continue;

				FindTodoLists(project.url);
				return;
			}

			request.Method = Method.POST;
			var values = new {name = projectName, description = "Tasks automatically created from email!"};
			request.AddParameter("application/json", JsonConvert.SerializeObject(values), ParameterType.RequestBody); 
			request.RequestFormat = DataFormat.Json;

			response = _client.Execute<dynamic>(request);
			if (response.StatusCode != HttpStatusCode.Created)
				return;

			data = JsonConvert.DeserializeObject<dynamic>(response.Content);
			FindOrCreateTodoList(data.todolists.url);
		}

		void FindTodoLists(dynamic project)
		{
			var url = string.Format("{0}", project); //convert to string
			var request = new RestRequest(url);

			var response = _client.Execute<dynamic>(request);
			var data = JsonConvert.DeserializeObject<dynamic>(response.Content);
			FindOrCreateTodoList(data.todolists.url);
		}

		void FindOrCreateTodoList(dynamic todolists)
		{
			var name = DateTime.Now.ToLongDateString();
			var url = string.Format("{0}", todolists); //convert to string
			var request = new RestRequest(url);

			var response = _client.Execute<dynamic>(request);
			var data = JsonConvert.DeserializeObject<dynamic>(response.Content);
			foreach (var list in data)
			{
				if (list.name != name)
					continue;

				AddTodo(list.url);
				return;
			}

			request.Method = Method.POST;
			var values = new { name = name, description = "Tasks created " + name };
			request.AddParameter("application/json", JsonConvert.SerializeObject(values), ParameterType.RequestBody);
			request.RequestFormat = DataFormat.Json;

			response = _client.Execute<dynamic>(request);
			if (response.StatusCode != HttpStatusCode.Created)
				return;

			url = response.Headers.First(x => x.Name == "Location").Value;
			AddTodo(url);
		}

		void AddTodo(dynamic list)
		{
			var url = string.Format("{0}", list).Replace(".json", "/todos.json");
			var request = new RestRequest(url, Method.POST);
			
			var values = new { content = _task };
			request.AddParameter("application/json", JsonConvert.SerializeObject(values), ParameterType.RequestBody);
			request.RequestFormat = DataFormat.Json;

			var response = _client.Execute<dynamic>(request);
			if (response.StatusCode != HttpStatusCode.Created)
				return;
		}
	}
}
