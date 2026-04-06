FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY ["Acmp.sln", "./"]
COPY ["src/MyCompany.Security.MiniKms.Client/MyCompany.Security.MiniKms.Client.csproj", "src/MyCompany.Security.MiniKms.Client/"]
COPY ["src/MyCompany.Security.MiniKms/MyCompany.Security.MiniKms.csproj", "src/MyCompany.Security.MiniKms/"]

RUN dotnet restore "src/MyCompany.Security.MiniKms/MyCompany.Security.MiniKms.csproj"

COPY . .
RUN dotnet publish "src/MyCompany.Security.MiniKms/MyCompany.Security.MiniKms.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "MyCompany.Security.MiniKms.dll"]
