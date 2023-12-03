## Info 
1、项目支持SqlServer和Mysql，默认Mysql，在配置文件中可以设置："IsMysql": true,  
2、如果用mysql，直接执行update-database即可，迁移文件在data下的MigrationsMySql文件夹；    
3、如果不想用自带的迁移文件，先删掉data下的MigrationsMySql文件夹，然后执行（具体步骤在SeedData.cs中）；  

## 给个星星! ⭐️
如果你喜欢这个项目或者它帮助你, 请给 Star~（辛苦星咯）

*********************************************************




## Tips
```
 /*
  * 本项目同时支持Mysql和Sqlserver，我一直使用的是Mysql，所以Mysql的迁移文件已经配置好，在Data文件夹下，
  * 直接执行update-database xxxx,那三步即可。如果你使用sqlserver，可以先从迁移开始，下边有步骤
  * 
  * 当然你也可以把Data文件夹除了ApplicationDbContext.cs文件外都删掉，自己重新做迁移。
  * 迁移完成后，执行dotnet run /seed
  *  1、PM> add-migration InitialIdentityServerPersistedGrantDbMigrationMysql -c PersistedGrantDbContext -o Data/MigrationsMySql/IdentityServer/PersistedGrantDb 
     Build started...
     Build succeeded.
     To undo this action, use Remove-Migration.
     2、PM> update-database -c PersistedGrantDbContext
     Build started...
     Build succeeded.
     Applying migration '20200509165052_InitialIdentityServerPersistedGrantDbMigrationMysql'.
     Done.
     3、PM> add-migration InitialIdentityServerConfigurationDbMigrationMysql -c ConfigurationDbContext -o Data/MigrationsMySql/IdentityServer/ConfigurationDb
     Build started...
     Build succeeded.
     To undo this action, use Remove-Migration.
     4、PM> update-database -c ConfigurationDbContext
     Build started...
     Build succeeded.
     Applying migration '20200509165153_InitialIdentityServerConfigurationDbMigrationMysql'.
     Done.
     5、PM> add-migration AppDbMigration -c ApplicationDbContext -o Data/MigrationsMySql
     Build started...
     Build succeeded.
     To undo this action, use Remove-Migration.
     6、PM> update-database -c ApplicationDbContext
     Build started...
     Build succeeded.
     Applying migration '20200509165505_AppDbMigration'.
     Done.
  * 
  */



```



**************************************************************

  技术：

      * .Net8 MVC
      
      * EntityFramework Core
      
      * SqlServer/Mysql
    
      * IdentityServer4
    
      * Authentication and Authorization
    
      * OAuth2 and OpenId Connect
    
      * GrantTypes.Implicit
    
      * oidc-client


​      



 
