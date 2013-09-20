using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Text.RegularExpressions;
using System.Web.Http;
using RestSharp;

namespace Mailgun.Public
{
	public class ParseMailController : ApiController
	{
		// GET api/<controller>
		public IEnumerable<string> Get()
		{
			return new string[] { "value1", "value2" };
		}

		// GET api/<controller>/5
		public string Get(int id)
		{
			return "value";
		}

		// POST api/<controller>
		public HttpResponseMessage Post(FormDataCollection form)
		{
			var command = new InboundMail();
			command.Sender = form.Get("sender");
			command.Body = form.Get("body-plain");
			command.Stripped = form.Get("stripped-text");


			var lookfor = "I will complete";
			var rx = new Regex(@"(\S.+?[.!?])(?=\s+|$)");
			foreach (Match match in rx.Matches(command.Body))
			{
				var index = match.Value.IndexOf(lookfor);

				if (index >= 0)
				{
					var msg = match.Value.Replace(lookfor, "Complete");
					SendSimpleMessage(command.Sender, msg);
					break;
				}
			}

			return Request.CreateResponse(HttpStatusCode.Accepted);
		}

		public static IRestResponse SendSimpleMessage(string to, string message)
		{
			RestClient client = new RestClient();
			client.BaseUrl = "https://api.mailgun.net/v2";
			client.Authenticator =
					new HttpBasicAuthenticator("api",
											   "key-0gv-f3wxz2f0y6nbkc7s5ltjpdiicya1");
			RestRequest request = new RestRequest();
			request.AddParameter("domain",
								 "wyldeye.mailgun.org", ParameterType.UrlSegment);
			request.Resource = "wyldeye.mailgun.org/messages";
			request.AddParameter("from", "Task Bot <bot@wyldeye.mailgun.org>");
			request.AddParameter("to", to);
			request.AddParameter("subject", "You have a task");
			request.AddParameter("text", message);
			request.Method = Method.POST;
			return client.Execute(request);
		}

		// PUT api/<controller>/5
		public void Put(int id, [FromBody]string value)
		{
		}

		// DELETE api/<controller>/5
		public void Delete(int id)
		{
		}
	}

	public class InboundMail
	{
		public string Sender { get; set; }
		public string Recipient { get; set; }
		public string Subject { get; set; }
		public string Body { get; set; }
		public string Stripped { get; set; }
	}
}