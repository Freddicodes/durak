FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["game/game.csproj", "game/"]
RUN dotnet restore "game/game.csproj"
COPY . .
WORKDIR "/src/game"
RUN dotnet build "game.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "game.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "game.dll"]
