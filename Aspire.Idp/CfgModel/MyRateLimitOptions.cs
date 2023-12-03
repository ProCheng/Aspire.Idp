namespace Aspire.Idp.CfgModel;

public class MyRateLimitOptions
{
    public const string Cfg = "RateLimitOptions";

    /// <summary>
    /// ���������
    /// </summary>
    public int PermitLimit { get; set; } = 100;

    /// <summary>
    /// һ�����ڶ��ٷ���
    /// </summary>
    public int Window { get; set; } = 10;

    /// <summary>
    /// ������ʱ��
    /// </summary>
    public int ReplenishmentPeriod { get; set; } = 2;

    /// <summary>
    /// �Ŷ���
    /// </summary>
    public int QueueLimit { get; set; } = 2;

    /// <summary>
    /// �ֶδ�����
    /// </summary>
    public int SegmentsPerWindow { get; set; } = 8;

    /// <summary>
    /// ��������
    /// </summary>
    public int TokenLimit { get; set; } = 10;


    public int TokenLimit2 { get; set; } = 20;

    /// <summary>
    /// ��������
    /// </summary>
    public int TokensPerPeriod { get; set; } = 4;

    /// <summary>
    /// �Զ�����
    /// </summary>
    public bool AutoReplenishment { get; set; } = false;

    /// <summary>
    /// ���ʷ�����Ϣ
    /// </summary>
    public ExceededResponse QuotaExceededResponse { get; set; }
}

public class ExceededResponse
{
    public string ContentHtml { get; set; }
    public string ContentJson { get; set; }
    public int StatusCode { get; set; }
}


