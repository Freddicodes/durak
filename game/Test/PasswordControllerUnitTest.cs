using game.Utils;

namespace Test;

public class PasswordControllerUnitTest
{
    [Fact]
    public void HashStart()
    {
        Assert.Contains("HASH#", PasswordController.Hash("Test"));
    }

    [Fact]
    public void RetrievingPassword()
    {
        const string pw = "Test";
        Assert.True(PasswordController.Verify(pw, PasswordController.Hash(pw)));
    }

    [Fact]
    public void ThrowsExceptionForIllegalInput()
    {
        const string pw = "Test";
        var hash = PasswordController.Hash(pw);
        hash = hash.Replace("HASH#", "");
        Assert.Throws<NotSupportedException>(() => PasswordController.Verify(pw,hash));
    }
}
