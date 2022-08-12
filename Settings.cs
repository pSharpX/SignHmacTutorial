public sealed class Settings 
{
    public ACSSettings Acs { get; set; } = null!;
}

public sealed class ACSSettings
{
    public string Endpoint { get; set; } = null!;

    public string AccessKey { get; set; } = null!;
}