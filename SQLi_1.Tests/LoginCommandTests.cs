using System;
using System.Data;
using System.Data.SqlClient;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SQLi_1;

namespace SQLi_1.Tests
{
    /// <summary>
    /// Tests that verify the Login SQL command is built using parameterized
    /// queries and is therefore not vulnerable to SQL injection (CWE-89).
    ///
    /// Strategy: call the internal BuildLoginCommand helper directly so we can
    /// inspect the resulting SqlCommand object without requiring a live database.
    /// We verify:
    ///   1. The SQL text contains ONLY named parameter placeholders – never
    ///      raw user input.
    ///   2. Each placeholder is backed by a correctly typed SqlParameter.
    ///   3. Typical SQL injection payloads are stored as literal parameter
    ///      values, not spliced into the query string.
    /// </summary>
    [TestClass]
    public class LoginCommandTests
    {
        // ------------------------------------------------------------------ //
        //  1. SQL text must use parameter placeholders, not string values
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void BuildLoginCommand_SqlText_ContainsUsernameParameterPlaceholder()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            // The query must reference the named parameter, not the literal value.
            StringAssert.Contains(cmd.CommandText, "@username",
                "SQL text should use the @username parameter placeholder.");
        }

        [TestMethod]
        public void BuildLoginCommand_SqlText_ContainsPwdParameterPlaceholder()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            StringAssert.Contains(cmd.CommandText, "@pwd",
                "SQL text should use the @pwd parameter placeholder.");
        }

        [TestMethod]
        public void BuildLoginCommand_SqlText_DoesNotContainLiteralUsername()
        {
            const string username = "alice";
            var cmd = Program.BuildLoginCommand(username, "secret");

            // The raw username value must NOT appear inside the SQL text.
            Assert.IsFalse(cmd.CommandText.Contains("'" + username + "'"),
                "SQL text must not embed the username value as a string literal.");
            Assert.IsFalse(cmd.CommandText.Contains(username + "'"),
                "SQL text must not contain the username value followed by a quote.");
        }

        [TestMethod]
        public void BuildLoginCommand_SqlText_DoesNotContainLiteralPassword()
        {
            const string password = "s3cr3t";
            var cmd = Program.BuildLoginCommand("alice", password);

            Assert.IsFalse(cmd.CommandText.Contains("'" + password + "'"),
                "SQL text must not embed the password value as a string literal.");
        }

        // ------------------------------------------------------------------ //
        //  2. Parameters collection must be present and correctly configured
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void BuildLoginCommand_Parameters_ContainsTwoParameters()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            Assert.AreEqual(2, cmd.Parameters.Count,
                "The command must have exactly two parameters (@username and @pwd).");
        }

        [TestMethod]
        public void BuildLoginCommand_Parameters_ContainsUsernameParameter()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            Assert.IsTrue(cmd.Parameters.Contains("@username"),
                "Parameters collection must include @username.");
        }

        [TestMethod]
        public void BuildLoginCommand_Parameters_ContainsPwdParameter()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            Assert.IsTrue(cmd.Parameters.Contains("@pwd"),
                "Parameters collection must include @pwd.");
        }

        [TestMethod]
        public void BuildLoginCommand_UsernameParameter_HasCorrectValue()
        {
            const string username = "alice";
            var cmd = Program.BuildLoginCommand(username, "secret");

            Assert.AreEqual(username, cmd.Parameters["@username"].Value,
                "@username parameter must carry the supplied username value.");
        }

        [TestMethod]
        public void BuildLoginCommand_PwdParameter_HasCorrectValue()
        {
            const string password = "P@ssw0rd!";
            var cmd = Program.BuildLoginCommand("alice", password);

            Assert.AreEqual(password, cmd.Parameters["@pwd"].Value,
                "@pwd parameter must carry the supplied password value.");
        }

        [TestMethod]
        public void BuildLoginCommand_UsernameParameter_IsNVarChar()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            Assert.AreEqual(SqlDbType.NVarChar, cmd.Parameters["@username"].SqlDbType,
                "@username parameter must have NVarChar type.");
        }

        [TestMethod]
        public void BuildLoginCommand_PwdParameter_IsNVarChar()
        {
            var cmd = Program.BuildLoginCommand("alice", "secret");

            Assert.AreEqual(SqlDbType.NVarChar, cmd.Parameters["@pwd"].SqlDbType,
                "@pwd parameter must have NVarChar type.");
        }

        // ------------------------------------------------------------------ //
        //  3. SQL injection payloads must be stored as parameter values, not
        //     embedded in the SQL string (regression / attack-vector tests)
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void BuildLoginCommand_ClassicSqlInjectionUsername_IsStoredAsParameterNotInSql()
        {
            // Classic authentication bypass: ' OR '1'='1
            const string injectionPayload = "' OR '1'='1";
            var cmd = Program.BuildLoginCommand(injectionPayload, "anything");

            // The payload must NOT appear in the query text.
            Assert.IsFalse(cmd.CommandText.Contains(injectionPayload),
                "SQL injection payload in username must not appear in the SQL text.");

            // The payload must be safely stored as a parameter value.
            Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value,
                "The raw payload should be the parameter value (harmless to the DB driver).");
        }

        [TestMethod]
        public void BuildLoginCommand_ClassicSqlInjectionPassword_IsStoredAsParameterNotInSql()
        {
            // Authentication bypass via password field.
            const string injectionPayload = "' OR '1'='1' --";
            var cmd = Program.BuildLoginCommand("admin", injectionPayload);

            Assert.IsFalse(cmd.CommandText.Contains(injectionPayload),
                "SQL injection payload in password must not appear in the SQL text.");

            Assert.AreEqual(injectionPayload, cmd.Parameters["@pwd"].Value,
                "The raw payload should be the parameter value (harmless to the DB driver).");
        }

        [TestMethod]
        public void BuildLoginCommand_UnionBasedInjection_IsStoredAsParameterNotInSql()
        {
            // UNION-based data exfiltration attempt.
            const string injectionPayload = "admin' UNION SELECT null, null, null --";
            var cmd = Program.BuildLoginCommand(injectionPayload, "pass");

            Assert.IsFalse(cmd.CommandText.Contains("UNION"),
                "UNION keyword from user input must not appear in the SQL text.");

            Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value);
        }

        [TestMethod]
        public void BuildLoginCommand_StatementsTerminator_IsStoredAsParameterNotInSql()
        {
            // Attempt to terminate the statement and append a DROP TABLE command.
            const string injectionPayload = "'; DROP TABLE Users; --";
            var cmd = Program.BuildLoginCommand(injectionPayload, "pass");

            Assert.IsFalse(cmd.CommandText.Contains("DROP TABLE"),
                "DROP TABLE from user input must not appear in the SQL text.");

            Assert.AreEqual(injectionPayload, cmd.Parameters["@username"].Value);
        }

        [TestMethod]
        public void BuildLoginCommand_SpecialCharactersInUsername_DoNotAlterQueryStructure()
        {
            // Characters that would break string-concatenated queries.
            const string specialChars = "O'Brien & Associates\" <script>";
            var cmd = Program.BuildLoginCommand(specialChars, "pass");

            // The command text must remain unchanged regardless of input.
            const string expectedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
            Assert.AreEqual(expectedSql, cmd.CommandText,
                "Special characters in input must not alter the SQL command text.");
        }

        [TestMethod]
        public void BuildLoginCommand_SpecialCharactersInPassword_DoNotAlterQueryStructure()
        {
            const string specialChars = "p@ss'w\"ord;--";
            var cmd = Program.BuildLoginCommand("alice", specialChars);

            const string expectedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
            Assert.AreEqual(expectedSql, cmd.CommandText,
                "Special characters in password must not alter the SQL command text.");
        }

        // ------------------------------------------------------------------ //
        //  4. Functional correctness – normal login inputs produce a valid cmd
        // ------------------------------------------------------------------ //

        [TestMethod]
        public void BuildLoginCommand_NormalCredentials_ReturnsNonNullCommand()
        {
            var cmd = Program.BuildLoginCommand("bob", "C0mpl3x!");

            Assert.IsNotNull(cmd, "BuildLoginCommand must return a non-null SqlCommand.");
        }

        [TestMethod]
        public void BuildLoginCommand_NormalCredentials_CommandTextIsCorrectSelectStatement()
        {
            var cmd = Program.BuildLoginCommand("bob", "C0mpl3x!");

            const string expectedSql = "SELECT * FROM Users WHERE username = @username AND pwd = @pwd";
            Assert.AreEqual(expectedSql, cmd.CommandText,
                "The SQL command text must match the expected parameterized query.");
        }

        [TestMethod]
        public void BuildLoginCommand_EmptyUsername_DoesNotCrash()
        {
            // Edge case: empty username should still produce a valid command.
            var cmd = Program.BuildLoginCommand(string.Empty, "pass");

            Assert.IsNotNull(cmd);
            Assert.AreEqual(string.Empty, cmd.Parameters["@username"].Value);
        }

        [TestMethod]
        public void BuildLoginCommand_EmptyPassword_DoesNotCrash()
        {
            var cmd = Program.BuildLoginCommand("alice", string.Empty);

            Assert.IsNotNull(cmd);
            Assert.AreEqual(string.Empty, cmd.Parameters["@pwd"].Value);
        }
    }
}
