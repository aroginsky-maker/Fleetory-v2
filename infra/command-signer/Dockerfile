# Official runtime manifest verified when this deployment profile was introduced.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:de0ee358cdd672f7017a003bed21e9ac9ed48a27c922a59b18175b6e82fa7fee
WORKDIR /app
COPY publish/ ./
COPY entrypoint.sh ./entrypoint.sh
RUN chmod 0555 /app/entrypoint.sh
ENV DOTNET_ENVIRONMENT=Production DOTNET_EnableDiagnostics=0 ASPNETCORE_HTTP_PORTS=""
USER $APP_UID
EXPOSE 9443
ENTRYPOINT ["/app/entrypoint.sh"]
