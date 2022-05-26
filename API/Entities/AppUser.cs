namespace API.Entities;

public class AppUser
{
    public int Id { get; set; }
    public string UserName { get; init; } = null!;
    public byte[] PasswordHash { get; init; } = null!;
    public byte[] PasswordSalt { get; init; } = null!;
}