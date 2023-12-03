git pull;
rm -rf .PublishFiles;
dotnet build;
dotnet publish -o /home/Aspire.Idp/Aspire.Idp/bin/Debug/netcoreapp3.1;
cp -r /home/Aspire.Idp/Aspire.Idp/bin/Debug/netcoreapp3.1 .PublishFiles;
echo "Successfully!!!! ^ please see the file .PublishFiles";