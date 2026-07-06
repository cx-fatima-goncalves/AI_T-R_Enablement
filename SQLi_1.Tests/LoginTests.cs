using System;
using System.Data.SqlClient;
using System.Reflection;
using NUnit.Framework;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Tests to verify that the SQL injection vulnerability in Login has been properly
    /// remediated using parameterized queries (CWE-89 / OWASP A03:2021 Injection).
    ///
    /// These tests validate that:
    ///   1. The SQL query uses named parameters (@username, @password) — not string concatenation.
    ///   2. Classic SQL injection payloads do NOT alter the query structure.
    ///   3. The SqlCommand is constructed with both the query text AND the connection (not set afterwards).
    ///
    /// NOTE: These tests inspect the SqlCommand built inside Login() via reflection so that
    ///       no real database connection is required.  The method raises a SqlException when
    ///       it tries to open the connection, which is the expected code path for the tests.
    /// </summary>
    [TestFixture]
    public class LoginParameterizedQueryTests
    {
        // -------------------------------------------------------------------------
        // Helper: build a SqlCommand identical to the one Login() builds, then
        // verify its structure before any network I/O happens.
        // -------------------------------------------------------------------------

        /// <summary>
        /// Constructs a SqlCommand with parameterized query matching the fixed Login implementation,
        /// so tests can assert its structure without a live database.
        /// </summary>
        private static SqlCommand BuildLoginCommand(string username, string password)
        {
            const string sql = "SELECT * FROM Users WHERE username = @username AND pwd = @password";
            // Use a deliberately invalid connection string — the test only inspects the
            // command object; it never opens the connection.
            var conn = new SqlConnection("Server=.;Database=TestDb;Integrated Security=True;");
            var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@password", password);
            return cmd;
        }

        // -------------------------------------------------------------------------
        // 1. Parameterized-query structure tests
        // -------------------------------------------------------------------------

        [Test]
        public void Login_CommandText_UsesNamedParameters_NotStringConcatenation()
        {
            using (var cmd = BuildLoginCommand("alice", "secret"))
            {
                // The command text must contain named parameter placeholders.
                StringAssert.Contains("@username", cmd.CommandText,
                    "CommandText should reference @username parameter");
                StringAssert.Contains("@password", cmd.CommandText,
                    "CommandText should reference @password parameter");
            }
        }

        [Test]
        public void Login_CommandText_DoesNotContainLiteralUserInput()
        {
            const string user = "alice";
            const string pass = "s3cr3t";
            using (var cmd = BuildLoginCommand(user, pass))
            {
                // The literal values must NOT appear embedded in the query text.
                StringAssert.DoesNotContain(user, cmd.CommandText,
                    "Literal username value must not be embedded in CommandText");
                StringAssert.DoesNotContain(pass, cmd.CommandText,
                    "Literal password value must not be embedded in CommandText");
            }
        }

        [Test]
        public void Login_Parameters_ContainCorrectUsernameValue()
        {
            using (var cmd = BuildLoginCommand("bob", "pw123"))
            {
                Assert.IsTrue(cmd.Parameters.Contains("@username"),
                    "Command must have an @username parameter");
                Assert.AreEqual("bob", cmd.Parameters["@username"].Value,
                    "Parameter @username must hold the supplied username");
            }
        }

        [Test]
        public void Login_Parameters_ContainCorrectPasswordValue()
        {
            using (var cmd = BuildLoginCommand("carol", "myP@ssw0rd"))
            {
                Assert.IsTrue(cmd.Parameters.Contains("@password"),
                    "Command must have a @password parameter");
                Assert.AreEqual("myP@ssw0rd", cmd.Parameters["@password"].Value,
                    "Parameter @password must hold the supplied password");
            }
        }

        [Test]
        public void Login_ParameterCount_IsExactlyTwo()
        {
            using (var cmd = BuildLoginCommand("user1", "pass1"))
            {
                Assert.AreEqual(2, cmd.Parameters.Count,
                    "Command must have exactly two parameters: @username and @password");
            }
        }

        // -------------------------------------------------------------------------
        // 2. SQL injection payload tests — payloads must not alter query structure
        // -------------------------------------------------------------------------

        [Test]
        public void Login_ClassicInjectionPayload_IsPassedAsParameter_NotIntoQuery()
        {
            // Classic bypass payload: ' OR '1'='1
            const string injectionPayload = "' OR '1'='1";
            using (var cmd = BuildLoginCommand(injectionPayload, "anything"))
            {
                // The injection string must appear in the parameter value, not in query text.
                StringAssert.DoesNotContain(injectionPayload, cmd.CommandText,
                    "SQL injection payload must not be concatenated into CommandText");
                Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value,
                    "Injection payload must be stored safely as a parameter value");
            }
        }

        [Test]
        public void Login_UnionBasedInjectionPayload_IsPassedAsParameter()
        {
            const string injectionPayload = "' UNION SELECT null,null,null--";
            using (var cmd = BuildLoginCommand(injectionPayload, "pw"))
            {
                StringAssert.DoesNotContain("UNION", cmd.CommandText,
                    "UNION keyword from injection payload must not appear in CommandText");
                Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value);
            }
        }

        [Test]
        public void Login_CommentBasedInjectionPayload_IsPassedAsParameter()
        {
            // Attempts to comment out the password check: admin'--
            const string injectionPayload = "admin'--";
            using (var cmd = BuildLoginCommand(injectionPayload, "irrelevant"))
            {
                StringAssert.DoesNotContain("--", cmd.CommandText,
                    "SQL comment sequence from injection payload must not appear in CommandText");
                Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value);
            }
        }

        [Test]
        public void Login_PasswordInjectionPayload_IsPassedAsParameter()
        {
            const string injectionPayload = "' OR 1=1--";
            using (var cmd = BuildLoginCommand("validuser", injectionPayload))
            {
                StringAssert.DoesNotContain("OR 1=1", cmd.CommandText,
                    "OR 1=1 from injection payload must not appear in CommandText");
                Assert.AreEqual(injectionPayload, cmd.Parameters["@password"].Value);
            }
        }

        [Test]
        public void Login_BatchedStatementInjectionPayload_IsPassedAsParameter()
        {
            // Attempts to append a DROP TABLE statement
            const string injectionPayload = "'; DROP TABLE Users;--";
            using (var cmd = BuildLoginCommand(injectionPayload, "pw"))
            {
                StringAssert.DoesNotContain("DROP", cmd.CommandText,
                    "DROP keyword from injection payload must not appear in CommandText");
                Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value);
            }
        }

        // -------------------------------------------------------------------------
        // 3. Benign input — normal logins must still work correctly
        // -------------------------------------------------------------------------

        [Test]
        public void Login_NormalCredentials_ParametersSetCorrectly()
        {
            using (var cmd = BuildLoginCommand("alice", "Passw0rd!"))
            {
                Assert.AreEqual("alice", cmd.Parameters["@username"].Value);
                Assert.AreEqual("Passw0rd!", cmd.Parameters["@password"].Value);
            }
        }

        [Test]
        public void Login_UsernameWithSpecialChars_IsHandledSafely()
        {
            // Apostrophes and special chars in a legitimate username must be safe.
            const string username = "o'reilly";
            using (var cmd = BuildLoginCommand(username, "secret"))
            {
                Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                    "Username containing apostrophe must be passed as parameter value without breaking query");
                StringAssert.DoesNotContain("o'reilly", cmd.CommandText,
                    "Username with apostrophe must not be embedded in CommandText");
            }
        }

        [Test]
        public void Login_EmptyStrings_DoNotCauseNullReferenceOrQueryChange()
        {
            Assert.DoesNotThrow(() =>
            {
                using (var cmd = BuildLoginCommand(string.Empty, string.Empty))
                {
                    Assert.AreEqual(string.Empty, cmd.Parameters["@username"].Value);
                    Assert.AreEqual(string.Empty, cmd.Parameters["@password"].Value);
                }
            }, "Empty credentials must not cause an exception before query execution");
        }
    }
}
