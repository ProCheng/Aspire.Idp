using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Blog.Core.Common.Helper
{
    public class GetNetData
    {
        public static string Get(string serviceAddress)
        {

            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = client.GetAsync(serviceAddress).Result;

                if (response.IsSuccessStatusCode)
                {
                    return response.Content.ReadAsStringAsync().Result;
                }
                else
                {
                    // Handle error if needed
                    Console.WriteLine($"Error: {response.StatusCode}");
                    return null;
                }
            }
        }

        public static string Post(string serviceAddress)
        {

            using (HttpClient client = new HttpClient())
            {
                string strContent = @"{ ""mmmm"": ""89e"",""nnnnnn"": ""0101943"",""kkkkkkk"": ""e8sodijf9""}";
                StringContent content = new StringContent(strContent, Encoding.UTF8, "application/json");

                HttpResponseMessage response = client.PostAsync(serviceAddress, content).Result;

                if (response.IsSuccessStatusCode)
                {
                    return response.Content.ReadAsStringAsync().Result;
                }
                else
                {
                    // Handle error if needed
                    Console.WriteLine($"Error: {response.StatusCode}");
                    return null;
                }
            }

            //解析josn
            //JObject jo = JObject.Parse(retString);
            //Response.Write(jo["message"]["mmmm"].ToString());

        }
    }


}
