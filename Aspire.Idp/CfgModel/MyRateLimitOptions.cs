namespace Aspire.Idp.CfgModel;

public class MyRateLimitOptions
{
    public const string Cfg = "RateLimitOptions";

    /// <summary>
    /// 允许多少条
    /// </summary>
    public int PermitLimit { get; set; } = 100;

    /// <summary>
    /// 一个窗口多少分钟
    /// </summary>
    public int Window { get; set; } = 10;

    /// <summary>
    /// 补充期时间
    /// </summary>
    public int ReplenishmentPeriod { get; set; } = 2;

    /// <summary>
    /// 排队数
    /// </summary>
    public int QueueLimit { get; set; } = 2;

    /// <summary>
    /// 分段窗口数
    /// </summary>
    public int SegmentsPerWindow { get; set; } = 8;

    /// <summary>
    /// 令牌限制
    /// </summary>
    public int TokenLimit { get; set; } = 10;


    public int TokenLimit2 { get; set; } = 20;

    /// <summary>
    /// 令牌周期
    /// </summary>
    public int TokensPerPeriod { get; set; } = 4;

    /// <summary>
    /// 自动补充
    /// </summary>
    public bool AutoReplenishment { get; set; } = false;

    /// <summary>
    /// 速率返回信息
    /// </summary>
    public ExceededResponse QuotaExceededResponse { get; set; }
}

public class ExceededResponse
{
    public string ContentHtml { get; set; }
    public string ContentJson { get; set; }
    public int StatusCode { get; set; }
}


