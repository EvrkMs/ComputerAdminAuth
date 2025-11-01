# Restore stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS restore
WORKDIR /src

COPY ComputerAdminAuth.sln ./
COPY NuGet.config ./
COPY Auth.Host/Auth.Host.csproj Auth.Host/
COPY Auth.Infrastructure/Auth.Infrastructure.csproj Auth.Infrastructure/
COPY Auth.EntityFramework/Auth.EntityFramework.csproj Auth.EntityFramework/
COPY Auth.Application/Auth.Application.csproj Auth.Application/
COPY Auth.Domain/Auth.Domain.csproj Auth.Domain/
COPY Auth.TelegramAuth/Auth.TelegramAuth.csproj Auth.TelegramAuth/
COPY Auth.Shared.Contracts/Auth.Shared.Contracts.csproj Auth.Shared.Contracts/
COPY Auth.Tests/Auth.Tests.csproj Auth.Tests/

RUN dotnet restore ./Auth.Host/Auth.Host.csproj --nologo --configfile ./NuGet.config

# Bring in sources
FROM restore AS source
COPY . ./

# Test stage (used by CI to validate build)
FROM source AS test
RUN mkdir -p /src/TestResults/Coverage \
    && SKIP_DB_TESTS=true dotnet test ./Auth.Tests/Auth.Tests.csproj \
        --no-restore \
        --configuration Release \
        --logger "trx;LogFileName=test_results.trx" \
        --results-directory /src/TestResults \
        -p:CollectCoverage=true \
        -p:CoverletOutputFormat=cobertura \
        -p:CoverletOutput=/src/TestResults/Coverage/

# Publish stage
FROM source AS publish
RUN dotnet publish ./Auth.Host/Auth.Host.csproj -c Release -o /app/publish --no-restore --nologo --configfile ./NuGet.config

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app

# Configure ASP.NET Core to listen HTTP internally; HTTPS is terminated at reverse proxy (nginx)
ENV ASPNETCORE_URLS=https://+:5001 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=true

COPY --from=publish /app/publish ./

# No ports published by default; can be exposed to other containers
EXPOSE 5001

ENTRYPOINT ["dotnet", "Auth.Host.dll"]
