#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 5004

FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
WORKDIR /src
COPY ["Aspire.Idp/Aspire.Idp.csproj", "Aspire.Idp/"]
RUN dotnet restore "Aspire.Idp/Aspire.Idp.csproj"
COPY . .
WORKDIR "/src/Aspire.Idp"
RUN dotnet build "Aspire.Idp.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Aspire.Idp.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Aspire.Idp.dll"]