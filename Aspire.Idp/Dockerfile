FROM swr.cn-south-1.myhuaweicloud.com/mcr/aspnet:3.1-alpine
WORKDIR /app
COPY . . 
EXPOSE 5004 
ENTRYPOINT ["dotnet", "Aspire.Idp.dll","-b","0.0.0.0"]