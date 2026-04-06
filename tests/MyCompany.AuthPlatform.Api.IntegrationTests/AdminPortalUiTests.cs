using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Microsoft.Playwright;
using Xunit;

namespace MyCompany.AuthPlatform.Api.IntegrationTests;

public sealed class AdminPortalUiTests
{
    [UiFact]
    [Trait("Category", "UI")]
    public async Task Operator_CanCreateRecipientBinding_AndIssueServicePackage_FromAdminPortal()
    {
        await using var fixture = await AdminPortalUiFixture.StartAsync();
        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });
        await using var context = await browser.NewContextAsync(new BrowserNewContextOptions
        {
            AcceptDownloads = true
        });
        var page = await context.NewPageAsync();
        using var rsa = RSA.Create(3072);
        var publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
        var bindingName = $"orders-api-ui-rsa-{Guid.NewGuid():N}".Substring(0, 27);
        var downloadDirectory = CreateTemporaryDirectory();

        try
        {
            await LoginAsync(page, fixture.RootUri, "operator.demo", "OperatorPass!123");

            await page.GetByRole(AriaRole.Link, new() { Name = "Recipient Bindings" }).ClickAsync();
            await page.Locator("#create-binding-form").WaitForAsync(new LocatorWaitForOptions
            {
                State = WaitForSelectorState.Visible
            });

            await page.SelectOptionAsync("#binding-client-select", new SelectOptionValue
            {
                Label = "orders-api | Orders API"
            });
            await page.SelectOptionAsync("#binding-type-select", "ExternalRsaPublicKey");
            await page.Locator("#create-binding-form input[name='bindingName']").FillAsync(bindingName);
            await page.Locator("#create-binding-form textarea[name='publicKeyPem']").FillAsync(publicKeyPem);
            await page.Locator("#create-binding-form input[name='keyId']")
                .EvaluateAsync("(element, value) => element.value = value", "orders-api-prod-rsa");
            await page.Locator("#create-binding-form input[name='keyVersion']")
                .EvaluateAsync("(element, value) => element.value = value", "2026q2");
            await page.GetByRole(AriaRole.Button, new() { Name = "Create Binding" }).ClickAsync();

            await ExpectAlertAsync(page, "Recipient binding created.");
            await ExpectVisibleAsync(page.Locator("#binding-table-body tr").Filter(new() { HasText = bindingName }));

            await page.GetByRole(AriaRole.Link, new() { Name = "Clients & Credentials" }).ClickAsync();
            var credentialRow = page.Locator("#credential-table-body tr").Filter(new() { HasText = "key-uat-orders-0002" });
            await ExpectVisibleAsync(credentialRow);

            var dialogResponses = new Queue<string?>([
                "UI service package issuance.",
                "binding",
                "1"
            ]);

            page.Dialog += async (_, dialog) =>
            {
                var response = dialogResponses.Count > 0 ? dialogResponses.Dequeue() : string.Empty;
                await dialog.AcceptAsync(response);
            };

            var download = await page.RunAndWaitForDownloadAsync(async () =>
            {
                await credentialRow.Locator("button[data-action='service-package']").ClickAsync();
            });

            var downloadPath = Path.Combine(downloadDirectory, download.SuggestedFilename);
            await download.SaveAsAsync(downloadPath);
            await ExpectAlertAsync(page, "Service package downloaded.");

            Assert.True(File.Exists(downloadPath));
            using var packageDocument = JsonDocument.Parse(await File.ReadAllTextAsync(downloadPath));
            var packageRoot = packageDocument.RootElement;
            Assert.Equal("ServiceValidation", packageRoot.GetProperty("packageType").GetString());
            Assert.Equal("ExternalRsaPublicKey", packageRoot.GetProperty("protectionBinding").GetProperty("bindingType").GetString());
            Assert.Equal("orders-api-prod-rsa", packageRoot.GetProperty("protectionBinding").GetProperty("keyId").GetString());
            Assert.Equal("2026q2", packageRoot.GetProperty("protectionBinding").GetProperty("keyVersion").GetString());
        }
        finally
        {
            Directory.Delete(downloadDirectory, recursive: true);
        }
    }

    [UiFact]
    [Trait("Category", "UI")]
    public async Task Viewer_CannotSeeBindingOrCredentialManagementActions_InAdminPortal()
    {
        await using var fixture = await AdminPortalUiFixture.StartAsync();
        using var playwright = await Playwright.CreateAsync();
        await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true
        });
        await using var context = await browser.NewContextAsync();
        var page = await context.NewPageAsync();

        await LoginAsync(page, fixture.RootUri, "viewer.demo", "ViewerPass!123");

        await ExpectHiddenAsync(page.GetByRole(AriaRole.Link, new() { Name = "Recipient Bindings" }));
        await ExpectHiddenAsync(page.GetByRole(AriaRole.Link, new() { Name = "Admin Users" }));
        await ExpectHiddenAsync(page.GetByRole(AriaRole.Link, new() { Name = "Audit Log" }));
        await ExpectHiddenAsync(page.Locator("#create-client-card"));
        await ExpectHiddenAsync(page.Locator("#issue-credential-card"));
        await page.GetByRole(AriaRole.Link, new() { Name = "Clients & Credentials" }).ClickAsync();
        await ExpectVisibleAsync(page.Locator("section[data-section='clients']"));
        var ordersRow = page.Locator("#client-table-body tr").Filter(new() { HasText = "orders-api" });
        await ExpectVisibleAsync(ordersRow);
        await ordersRow.GetByRole(AriaRole.Button, new() { Name = "Credentials" })
            .EvaluateAsync("button => button.click()");
        await ExpectVisibleAsync(page.Locator("#credential-table-body tr").Filter(new() { HasText = "key-uat-orders-0002" }));
        var credentialTableText = await page.Locator("#credential-table-body").TextContentAsync();
        Assert.Contains("Read only", credentialTableText ?? string.Empty, StringComparison.Ordinal);
        Assert.Equal(0, await page.Locator("button[data-action='service-package']").CountAsync());
        Assert.Equal(0, await page.Locator("button[data-action='client-package']").CountAsync());
    }

    private static async Task LoginAsync(IPage page, string rootUri, string username, string password)
    {
        await page.GotoAsync($"{rootUri}/admin/login.html");
        await page.Locator("#login-form-host form").WaitForAsync(new LocatorWaitForOptions
        {
            State = WaitForSelectorState.Visible
        });
        await page.Locator("#username").FillAsync(username);
        await page.Locator("#password").FillAsync(password);
        await page.GetByRole(AriaRole.Button, new() { Name = "Sign In" }).ClickAsync();
        await page.WaitForURLAsync("**/admin/index.html");
        await page.Locator("#section-title").WaitForAsync(new LocatorWaitForOptions
        {
            State = WaitForSelectorState.Visible
        });
    }

    private static async Task ExpectAlertAsync(IPage page, string message)
    {
        await ExpectVisibleAsync(page.Locator("#alert-host .alert").Filter(new() { HasText = message }).First);
    }

    private static async Task ExpectVisibleAsync(ILocator locator)
    {
        await locator.WaitForAsync(new LocatorWaitForOptions
        {
            State = WaitForSelectorState.Visible
        });
        Assert.True(await locator.IsVisibleAsync());
    }

    private static async Task ExpectHiddenAsync(ILocator locator)
    {
        Assert.False(await locator.IsVisibleAsync());
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"acmp-ui-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class UiFactAttribute : FactAttribute
    {
        public UiFactAttribute()
        {
            if (!string.Equals(
                Environment.GetEnvironmentVariable("RUN_UI_TESTS"),
                "true",
                StringComparison.OrdinalIgnoreCase))
            {
                Skip = "Set RUN_UI_TESTS=true and install Playwright Chromium to run admin portal UI tests.";
            }
        }
    }

    private sealed class AdminPortalUiFixture : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly StringBuilder _output = new();

        private AdminPortalUiFixture(Process process, string rootUri)
        {
            _process = process;
            RootUri = rootUri;
        }

        public string RootUri { get; }

        public static async Task<AdminPortalUiFixture> StartAsync()
        {
            var rootUri = $"http://127.0.0.1:{GetFreeTcpPort()}";
            var apiProjectDirectory = Path.Combine(GetRepositoryRoot(), "src", "MyCompany.AuthPlatform.Api");
            var targetFrameworkDirectory = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            var configurationDirectory = targetFrameworkDirectory.Parent?.Name
                ?? throw new InvalidOperationException("The integration test configuration directory could not be resolved.");
            var apiAssemblyPath = Path.Combine(apiProjectDirectory, "bin", configurationDirectory, targetFrameworkDirectory.Name, "MyCompany.AuthPlatform.Api.dll");
            var startInfo = new ProcessStartInfo("dotnet", $"\"{apiAssemblyPath}\" --urls {rootUri}")
            {
                WorkingDirectory = apiProjectDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
            startInfo.Environment["Persistence__Provider"] = "InMemoryDemo";
            startInfo.Environment["DemoMode__SeedOnStartup"] = "true";
            startInfo.Environment["Authentication__Mode"] = "EmbeddedIdentity";
            startInfo.Environment["Logging__EventLog__LogLevel__Default"] = "None";
            startInfo.Environment["DOTNET_LAUNCH_PROFILE"] = string.Empty;

            var process = new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true,
            };

            if (!process.Start())
            {
                throw new InvalidOperationException("The admin portal UI test host process could not be started.");
            }

            var fixture = new AdminPortalUiFixture(process, rootUri);
            process.OutputDataReceived += (_, args) => fixture.AppendOutput(args.Data);
            process.ErrorDataReceived += (_, args) => fixture.AppendOutput(args.Data);
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await fixture.WaitUntilReadyAsync();
            return fixture;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                    await _process.WaitForExitAsync();
                }
            }
            finally
            {
                _process.Dispose();
            }
        }

        private async Task WaitUntilReadyAsync()
        {
            using var client = new HttpClient
            {
                BaseAddress = new Uri(RootUri, UriKind.Absolute)
            };
            var lastFailureDetails = string.Empty;

            for (var attempt = 0; attempt < 50; attempt++)
            {
                try
                {
                    using var response = await client.GetAsync("/health");
                    if (response.IsSuccessStatusCode)
                    {
                        return;
                    }

                    lastFailureDetails = $"{(int)response.StatusCode} {response.ReasonPhrase} | {await response.Content.ReadAsStringAsync()}";
                }
                catch (Exception exception)
                {
                    lastFailureDetails = exception.Message;
                }

                if (_process.HasExited)
                {
                    break;
                }

                await Task.Delay(200);
            }

            throw new InvalidOperationException(
                $"The UI test host at '{RootUri}' did not become healthy in time. Last observed result: {lastFailureDetails}{Environment.NewLine}Process output:{Environment.NewLine}{_output}");
        }

        private void AppendOutput(string? data)
        {
            if (!string.IsNullOrWhiteSpace(data))
            {
                _output.AppendLine(data);
            }
        }

        private static int GetFreeTcpPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                return ((IPEndPoint)listener.LocalEndpoint).Port;
            }
            finally
            {
                listener.Stop();
            }
        }

        private static string GetRepositoryRoot() =>
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    }
}
