using System.Net;
using System.Numerics;
using System.Text;

namespace SRP;

public class SrpClient
{
   
    
    private readonly Func<byte[], byte[]> Hash;
    private readonly int generator;
    private readonly BigInteger BigN;

    private BigInteger a;
    public BigInteger A, ServerB;

    private byte[] saltFromServer;

    public SrpClient(Func<byte[], byte[]> H, int g, BigInteger N)
    {
        this.Hash = H;
        this.generator = g;
        this.BigN = N;
    }

    private byte[] GenerateSalt(int length)
    {
        var str = Helpers.RandomBigIntInString(length);
        return str.ToBytes();
    }
   
    public void Register(string I, string P, SrpServer server)
    {
        var salt = GenerateSalt(32);
        var x = GeneratePrivateKey(P, salt);
        var v = GenerateVerifier(x);
        Helpers.Log("salt", salt.ToString());
        Helpers.Log("x", x.ToString());
        Helpers.Log("v", v.ToString());
        
        
        server.RegisterNewUser(I, v, salt);
        
        Helpers.Log("Register", "Success");
    }

    public void SetSalt(byte[] s)
    {
        saltFromServer = s;
    }

    public void Login(string I, string P, SrpServer server)
    {
        LoginStep1(I, P, server);
        LoginStep2(P, server);
    }
    
    private void LoginStep1(string I, string P, SrpServer server)
    {
        GenerateA();
        ServerB = server.LoginStep1(I, A, this);
        Helpers.Log("Step 1", "Success");
    }

    private void LoginStep2(string P, SrpServer server)
    {
        var S = ComputeSessionKey(P);
        Helpers.Log("S", S.ToString());

        var M1 = GenerateClientProof(ServerB, S);
        
        var M2FromServer = server.LoginStep2(M1);

        ValidateServerProof(M2FromServer, M1, S);
        Helpers.Log("Step 2", "Success");
        Helpers.Log("Auth", "Complete");

    }
    
    private BigInteger GeneratePrivateKey(string P, byte[] salt)
    {
        return Hash(
            salt.
            Concat(
            Hash(
            Encoding
            .UTF8
            .GetBytes(P)))
            .ToArray())
            .ToSrpBigInt();
    }

    private BigInteger GenerateVerifier(BigInteger x)
    {
        var verifier = BigInteger.ModPow(generator, x, BigN);

        return verifier;
    }

    private BigInteger GenerateA()
    {
        a = Helpers.RandomBigIntInString(64).ToSrpBigInt();
        Helpers.Log("a", a.ToString());

        
        A = BigInteger.ModPow(generator, a, BigN);
        Helpers.Log("A", A.ToString());

        return A;
    }

    private BigInteger ComputeSessionKey(string P)
    {
        if (ServerB.IsZero) throw new Exception();
        
        var u = Helpers.ComputeU(Hash, A, ServerB);
        var x = GeneratePrivateKey(P, saltFromServer);
        var k = Helpers.ComputeK(generator, BigN, Hash);

        var exp = a + u * x;

        var val = mod(ServerB - (BigInteger.ModPow(generator, x, BigN) * k % BigN), BigN);

        return BigInteger.ModPow(val, exp, BigN);
    }
    
    private BigInteger GenerateClientProof(BigInteger B, BigInteger S)
    {
        return Helpers.ComputeClientProof(BigN, Hash, A, B, S);
    }

    public bool ValidateServerProof(BigInteger M2, BigInteger M1, BigInteger S)
    {
        return M2 == Helpers.ComputeServerProof(BigN, Hash, A, M1, S);
    }
    
    private BigInteger mod(BigInteger x, BigInteger m) {
        BigInteger r = x % m;
        return r < 0 ? r + m : r;
    }
}