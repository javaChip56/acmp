FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY ["Acmp.sln", "./"]
COPY ["src/MyCompany.Shared.Contracts/MyCompany.Shared.Contracts.csproj", "src/MyCompany.Shared.Contracts/"]
COPY ["src/MyCompany.AuthPlatform.Persistence.Abstractions/MyCompany.AuthPlatform.Persistence.Abstractions.csproj", "src/MyCompany.AuthPlatform.Persistence.Abstractions/"]
COPY ["src/MyCompany.AuthPlatform.Persistence.InMemory/MyCompany.AuthPlatform.Persistence.InMemory.csproj", "src/MyCompany.AuthPlatform.Persistence.InMemory/"]
COPY ["src/MyCompany.AuthPlatform.Persistence.SqlServer/MyCompany.AuthPlatform.Persistence.SqlServer.csproj", "src/MyCompany.AuthPlatform.Persistence.SqlServer/"]
COPY ["src/MyCompany.AuthPlatform.Persistence.Postgres/MyCompany.AuthPlatform.Persistence.Postgres.csproj", "src/MyCompany.AuthPlatform.Persistence.Postgres/"]
COPY ["src/MyCompany.AuthPlatform.Application/MyCompany.AuthPlatform.Application.csproj", "src/MyCompany.AuthPlatform.Application/"]
COPY ["src/MyCompany.AuthPlatform.Packaging/MyCompany.AuthPlatform.Packaging.csproj", "src/MyCompany.AuthPlatform.Packaging/"]
COPY ["src/MyCompany.AuthPlatform.Hmac/MyCompany.AuthPlatform.Hmac.csproj", "src/MyCompany.AuthPlatform.Hmac/"]
COPY ["src/MyCompany.AuthPlatform.Hmac.Client/MyCompany.AuthPlatform.Hmac.Client.csproj", "src/MyCompany.AuthPlatform.Hmac.Client/"]
COPY ["src/MyCompany.Security.MiniKms.Client/MyCompany.Security.MiniKms.Client.csproj", "src/MyCompany.Security.MiniKms.Client/"]
COPY ["src/MyCompany.AuthPlatform.Api/MyCompany.AuthPlatform.Api.csproj", "src/MyCompany.AuthPlatform.Api/"]

RUN dotnet restore "src/MyCompany.AuthPlatform.Api/MyCompany.AuthPlatform.Api.csproj"

COPY . .
RUN dotnet publish "src/MyCompany.AuthPlatform.Api/MyCompany.AuthPlatform.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "MyCompany.AuthPlatform.Api.dll"]
