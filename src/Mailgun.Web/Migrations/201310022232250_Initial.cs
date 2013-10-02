namespace Mailgun.Web.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class Initial : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.UserProfile",
                c => new
                    {
                        UserId = c.Int(nullable: false, identity: true),
                        UserName = c.String(),
                        BasecampCredentials_BasecampCredentialsId = c.Int(),
                    })
                .PrimaryKey(t => t.UserId)
                .ForeignKey("dbo.BasecampCredentials", t => t.BasecampCredentials_BasecampCredentialsId)
                .Index(t => t.BasecampCredentials_BasecampCredentialsId);
            
            CreateTable(
                "dbo.BasecampCredentials",
                c => new
                    {
                        BasecampCredentialsId = c.Int(nullable: false, identity: true),
                        AccessToken = c.String(),
                        RefreshToken = c.String(),
                    })
                .PrimaryKey(t => t.BasecampCredentialsId);
            
        }
        
        public override void Down()
        {
            DropIndex("dbo.UserProfile", new[] { "BasecampCredentials_BasecampCredentialsId" });
            DropForeignKey("dbo.UserProfile", "BasecampCredentials_BasecampCredentialsId", "dbo.BasecampCredentials");
            DropTable("dbo.BasecampCredentials");
            DropTable("dbo.UserProfile");
        }
    }
}
