using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace SQLi_1
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var user = args[0];
                var pwd = Encrypt(args[1]);
                Login(user, pwd);
				var password = "1!.Acjjjj";
				var password2 = "1!.Acjjjj";
            }
            catch
            {

                Console.WriteLine("An error has occurred !!");
            }

        }

        private static  string Encrypt(string plain)
        {
            return plain;
        }

        /// <summary>
        /// Builds a parameterized SqlCommand for the login query.
        /// Exposed as internal for testability.
        /// </summary>
        internal static SqlCommand BuildLoginCommand(string username, string password)
        {
            // Use parameterized query to prevent SQL injection.
            // User-supplied values are passed as typed SqlParameters, never
            // concatenated into the SQL string, so the database driver handles
            // escaping and the taint flow cannot reach the SQL interpreter.
            var sql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
            var cmd = new SqlCommand(sql);
            cmd.Parameters.Add(new SqlParameter("@username", System.Data.SqlDbType.NVarChar) { Value = username });
            cmd.Parameters.Add(new SqlParameter("@pwd", System.Data.SqlDbType.NVarChar) { Value = password });
            return cmd;
        }

        private static void Login(string username,string password)
        {
            try
            {
                using (var conn = new SqlConnection("conn..."))
                {
                    using (var cmd = BuildLoginCommand(username, password))
                    {
                        cmd.Connection = conn;
                        cmd.ExecuteScalar();
                    }

                }
            }
            catch
            {

                Console.WriteLine("An error has occurred !!");
            }

        }
    }
}
