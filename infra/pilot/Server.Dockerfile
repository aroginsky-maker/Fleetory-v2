FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee
WORKDIR /app
COPY publish/ /app/
ENV DOTNET_ENVIRONMENT=Production DOTNET_EnableDiagnostics=0 ASPNETCORE_URLS=""
USER $APP_UID
ENTRYPOINT ["dotnet", "/app/Fleetory.Server.dll"]
