using System;
using Mailgun.Web.Controllers;
using NUnit.Framework;

namespace Mailgun.Web.Tests
{
	[TestFixture]
	public class BasecampTryout
	{
		[Test]
		public void HitBasecamp()
		{
			const string token = "BAhbByIBuXsiZXhwaXJlc19hdCI6IjIwMTMtMTAtMDlUMjI6NTc6MzhaIiwidXNlcl9pZHMiOlsxNDA3NDYwOCwxODYwOTE1NV0sImNsaWVudF9pZCI6ImE5NzE4NTMwMmUwMzkyNmJjYzZkOGJjMmEwMDhiMWI0MjkzMjY4YzciLCJ2ZXJzaW9uIjoxLCJhcGlfZGVhZGJvbHQiOiJkN2RhNDI0N2YwZWY1ZGE3MjUxZTA3M2FmNWVjMWVjMiJ9dToJVGltZQ02ZRzAMipp5g==--e8da8fc12e002549da602cddad8a9c1f797e3724";
			const string task = "finish writing some code";

			var client = new BasecampClient();
			client.CreateTask(task, token);
		}
	}
}
